//! The typed SCL document tree.
//!
//! Each type mirrors one SCL element and is populated from the generic XML
//! tree by [`super::parse`]. Attributes absent from a document keep the
//! type's default, which is what the schema defaults amount to for everything
//! except the handful of attributes that default to true.

/// The document root.
#[derive(Debug, Clone, Default)]
pub struct Scl {
    pub version: String,
    pub revision: String,
    pub header: Header,
    pub communication: Option<Communication>,
    pub ieds: Vec<Ied>,
    pub data_type_templates: Option<DataTypeTemplates>,
}

/// Identifies the configuration file.
#[derive(Debug, Clone, Default)]
pub struct Header {
    pub id: String,
    pub version: String,
    pub revision: String,
    pub tool_id: String,
}

/// Describes subnetworks and the addresses of connected access points.
#[derive(Debug, Clone, Default)]
pub struct Communication {
    pub sub_networks: Vec<SubNetwork>,
}

/// One communication subnetwork.
#[derive(Debug, Clone, Default)]
pub struct SubNetwork {
    pub name: String,
    pub kind: String,
    pub connected_aps: Vec<ConnectedAp>,
}

/// Binds an IED access point to a subnetwork and carries its addresses and
/// GSE/SMV multicast parameters.
#[derive(Debug, Clone, Default)]
pub struct ConnectedAp {
    pub ied_name: String,
    pub ap_name: String,
    pub address: Option<Address>,
    pub gses: Vec<Gse>,
    pub smvs: Vec<Smv>,
}

/// A list of typed address parameters.
#[derive(Debug, Clone, Default)]
pub struct Address {
    pub ps: Vec<P>,
}

impl Address {
    /// Returns the value of the named parameter.
    ///
    /// Both the bare name and the `tP_`-prefixed form some tools emit are
    /// accepted.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.ps
            .iter()
            .find(|p| p.kind == name || p.kind == format!("tP_{name}"))
            .map(|p| p.value.trim())
    }
}

/// One address parameter, for example
/// `<P type="MAC-Address">01-0C-CD-01-00-01</P>`.
#[derive(Debug, Clone, Default)]
pub struct P {
    pub kind: String,
    pub value: String,
}

/// Carries the multicast address and timing of one GOOSE control block.
#[derive(Debug, Clone, Default)]
pub struct Gse {
    pub ld_inst: String,
    pub cb_name: String,
    pub address: Option<Address>,
    pub min_time: Option<DurUnits>,
    pub max_time: Option<DurUnits>,
}

/// Carries the multicast address of one sampled-value control block.
#[derive(Debug, Clone, Default)]
pub struct Smv {
    pub ld_inst: String,
    pub cb_name: String,
    pub address: Option<Address>,
}

/// A duration with unit and multiplier attributes.
///
/// Values are interpreted as milliseconds (unit `s`, multiplier `m`), the only
/// form seen in practice for GSE `MinTime` and `MaxTime`.
#[derive(Debug, Clone, Default)]
pub struct DurUnits {
    pub unit: String,
    pub multiplier: String,
    pub value: String,
}

impl DurUnits {
    /// Interprets the element as a count of milliseconds.
    pub fn millis(&self) -> u32 {
        self.value.trim().parse().unwrap_or(0)
    }
}

/// One physical device configuration.
#[derive(Debug, Clone, Default)]
pub struct Ied {
    pub name: String,
    pub kind: String,
    pub manufacturer: String,
    pub config_version: String,
    pub services: Option<Services>,
    pub access_points: Vec<AccessPoint>,
}

/// One communication access point of an IED.
#[derive(Debug, Clone, Default)]
pub struct AccessPoint {
    pub name: String,
    pub services: Option<Services>,
    pub server: Option<Server>,
}

/// Holds the logical devices visible through an access point.
#[derive(Debug, Clone, Default)]
pub struct Server {
    pub l_devices: Vec<LDevice>,
}

/// One logical device.
#[derive(Debug, Clone, Default)]
pub struct LDevice {
    pub inst: String,
    pub ln0: Option<Ln>,
    pub lns: Vec<Ln>,
}

impl LDevice {
    /// Returns every logical node, `LN0` first, which is the order a model is
    /// built in.
    pub fn all_lns(&self) -> impl Iterator<Item = &Ln> {
        self.ln0.iter().chain(self.lns.iter())
    }
}

/// A logical node instance (`LN` or `LN0`).
///
/// Control blocks and `Inputs` are decoded on every logical node, although
/// they normally appear on `LN0` only.
#[derive(Debug, Clone, Default)]
pub struct Ln {
    pub ln_class: String,
    pub inst: String,
    pub ln_type: String,
    pub prefix: String,

    pub dois: Vec<Doi>,

    pub data_sets: Vec<DataSet>,
    pub report_controls: Vec<ReportControl>,
    pub gse_controls: Vec<GseControl>,
    pub sampled_value_controls: Vec<SampledValueControl>,
    pub log_controls: Vec<LogControl>,
    pub setting_control: Option<SettingControl>,
    pub inputs: Option<Inputs>,
}

impl Ln {
    /// Returns the instance name the model uses: `LLN0`, or the prefix, class
    /// and instance concatenated.
    pub fn instance_name(&self) -> String {
        if self.ln_class == "LLN0" {
            return "LLN0".to_string();
        }
        format!("{}{}{}", self.prefix, self.ln_class, self.inst)
    }
}

/// An instantiated data object carrying initial values.
#[derive(Debug, Clone, Default)]
pub struct Doi {
    pub name: String,
    pub dais: Vec<Dai>,
    pub sdis: Vec<Sdi>,
}

/// Addresses a sub-object or a structured attribute inside a `DOI`.
#[derive(Debug, Clone, Default)]
pub struct Sdi {
    pub name: String,
    pub dais: Vec<Dai>,
    pub sdis: Vec<Sdi>,
}

/// An instantiated data attribute with optional values.
#[derive(Debug, Clone, Default)]
pub struct Dai {
    pub name: String,
    pub vals: Vec<Val>,
}

/// An initial value; `s_group` selects the setting group it applies to.
#[derive(Debug, Clone, Default)]
pub struct Val {
    pub s_group: String,
    pub value: String,
}

/// A dataset definition.
#[derive(Debug, Clone, Default)]
pub struct DataSet {
    pub name: String,
    pub desc: String,
    pub fcdas: Vec<Fcda>,
}

/// One dataset member reference.
#[derive(Debug, Clone, Default)]
pub struct Fcda {
    pub ld_inst: String,
    pub prefix: String,
    pub ln_class: String,
    pub ln_inst: String,
    pub do_name: String,
    pub da_name: String,
    pub fc: String,
}

/// Declares an IED's or access point's service capabilities.
///
/// Only the report-buffer capacity is read from it.
#[derive(Debug, Clone, Default)]
pub struct Services {
    pub conf_report_control: Option<ConfReportControl>,
}

/// The report-control capability.
///
/// `max_buf` is how many reports a buffered control block can retain, which
/// the server applies to the blocks that do not configure a depth of their
/// own.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConfReportControl {
    pub max: i32,
    pub max_buf: i32,
}

/// Configures a buffered or unbuffered report control block.
#[derive(Debug, Clone, Default)]
pub struct ReportControl {
    pub name: String,
    pub desc: String,
    pub rpt_id: String,
    pub dat_set: String,
    pub conf_rev: u32,
    pub buffered: bool,
    pub buf_time: u32,
    pub intg_pd: u32,
    pub trg_ops: Option<TrgOpsElem>,
    pub opt_fields: Option<OptFieldsElem>,
    pub rpt_enabled: Option<RptEnabled>,
}

/// Report and log trigger option flags.
///
/// `gi` defaults to true in the schema, so it is kept as an `Option` and
/// resolved by the builder rather than defaulting to false here.
#[derive(Debug, Clone, Default)]
pub struct TrgOpsElem {
    pub dchg: bool,
    pub qchg: bool,
    pub dupd: bool,
    pub period: bool,
    pub gi: bool,
}

/// Report optional field flags.
#[derive(Debug, Clone, Default)]
pub struct OptFieldsElem {
    pub seq_num: bool,
    pub time_stamp: bool,
    pub data_set: bool,
    pub reason_code: bool,
    pub data_ref: bool,
    pub entry_id: bool,
    pub config_ref: bool,
    pub buf_ovfl: bool,
    pub segmentation: bool,
}

/// Limits the number of report control block instances.
#[derive(Debug, Clone, Copy, Default)]
pub struct RptEnabled {
    pub max: i32,
}

/// Configures a GOOSE control block.
///
/// The `appID` attribute is the GoID string, not the Ethernet APPID, which
/// lives in `Communication/GSE`.
#[derive(Debug, Clone, Default)]
pub struct GseControl {
    pub name: String,
    pub desc: String,
    pub app_id: String,
    pub dat_set: String,
    pub conf_rev: u32,
    /// `GOOSE` (the default) or `GSSE`.
    pub kind: String,
}

/// Configures a sampled-value control block.
#[derive(Debug, Clone, Default)]
pub struct SampledValueControl {
    pub name: String,
    pub smv_id: String,
    pub dat_set: String,
    pub conf_rev: u32,
    pub smp_rate: u32,
    pub nof_asdu: u32,
    /// Defaults to true in the schema.
    pub multicast: bool,
}

/// Configures a log control block.
#[derive(Debug, Clone, Default)]
pub struct LogControl {
    pub name: String,
    pub dat_set: String,
    pub log_name: String,
    /// Defaults to true in the schema.
    pub log_ena: bool,
    pub intg_pd: u32,
    pub trg_ops: Option<TrgOpsElem>,
}

/// Declares the setting groups of a logical device.
#[derive(Debug, Clone, Copy, Default)]
pub struct SettingControlElem {
    pub num_of_sgs: u8,
    pub act_sg: u8,
}

/// Alias matching the SCL element name.
pub type SettingControl = SettingControlElem;

/// Lists the external references consumed by a logical node.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub ext_refs: Vec<ExtRef>,
}

/// Binds a local input to data published by another IED.
///
/// The `src*` attributes identify the publishing control block (Edition 2).
#[derive(Debug, Clone, Default)]
pub struct ExtRef {
    pub ied_name: String,
    pub ld_inst: String,
    pub prefix: String,
    pub ln_class: String,
    pub ln_inst: String,
    pub do_name: String,
    pub da_name: String,
    pub int_addr: String,
    pub service_type: String,
    pub src_ld_inst: String,
    pub src_prefix: String,
    pub src_ln_class: String,
    pub src_ln_inst: String,
    pub src_cb_name: String,
}

/// Holds the reusable type definitions.
#[derive(Debug, Clone, Default)]
pub struct DataTypeTemplates {
    pub ln_node_types: Vec<LNodeType>,
    pub do_types: Vec<DoType>,
    pub da_types: Vec<DaType>,
    pub enum_types: Vec<EnumType>,
}

/// A logical node type template.
#[derive(Debug, Clone, Default)]
pub struct LNodeType {
    pub id: String,
    pub ln_class: String,
    pub dos: Vec<Do>,
}

/// Declares a data object of a logical node type.
#[derive(Debug, Clone, Default)]
pub struct Do {
    pub name: String,
    pub kind: String,
    pub transient: bool,
}

/// A data object type template, a CDC specialisation.
#[derive(Debug, Clone, Default)]
pub struct DoType {
    pub id: String,
    pub cdc: String,
    pub das: Vec<Da>,
    pub sdos: Vec<Sdo>,
}

/// Declares a sub data object inside a `DOType`.
#[derive(Debug, Clone, Default)]
pub struct Sdo {
    pub name: String,
    pub kind: String,
}

/// Declares a data attribute inside a `DOType`.
///
/// `count` may be a number or, rarely, an enum value name; only numeric counts
/// are honoured.
#[derive(Debug, Clone, Default)]
pub struct Da {
    pub name: String,
    pub fc: String,
    pub btype: String,
    pub kind: String,
    pub count: String,
    pub dchg: bool,
    pub qchg: bool,
    pub dupd: bool,
    pub vals: Vec<Val>,
}

/// A constructed attribute type template.
#[derive(Debug, Clone, Default)]
pub struct DaType {
    pub id: String,
    pub bdas: Vec<Bda>,
}

/// Declares a member of a constructed attribute type.
#[derive(Debug, Clone, Default)]
pub struct Bda {
    pub name: String,
    pub btype: String,
    pub kind: String,
    pub count: String,
    pub vals: Vec<Val>,
}

/// An enumeration type template.
#[derive(Debug, Clone, Default)]
pub struct EnumType {
    pub id: String,
    pub enum_vals: Vec<EnumVal>,
}

impl EnumType {
    /// Returns the ordinal of the named literal.
    pub fn ord_of(&self, literal: &str) -> Option<i64> {
        self.enum_vals
            .iter()
            .find(|ev| ev.name.trim() == literal)
            .map(|ev| ev.ord)
    }
}

/// One enumeration literal.
#[derive(Debug, Clone, Default)]
pub struct EnumVal {
    pub ord: i64,
    pub name: String,
}

impl Scl {
    /// Returns the named IED, or the first one when `name` is empty.
    pub fn ied(&self, name: &str) -> Option<&Ied> {
        if name.is_empty() {
            return self.ieds.first();
        }
        self.ieds.iter().find(|i| i.name == name)
    }
}
