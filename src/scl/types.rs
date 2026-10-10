//! The typed SCL document tree.
//!
//! Each type mirrors one SCL element and is populated from the generic XML
//! tree by [`super::parse`]. Attributes absent from a document keep the
//! schema default: false for most booleans, and true for the handful the
//! schema defaults to true (`gi`, `multicast`, `logEna`, `reasonCode`,
//! `bufOvfl`, `indexed`), which the parser resolves.

use std::collections::BTreeMap;

use super::Edition;

/// The document root.
#[derive(Debug, Clone, Default)]
pub struct Scl {
    /// The default namespace the root element declares.
    pub xmlns: String,
    pub version: String,
    pub revision: String,
    pub release: String,
    pub header: Header,
    pub communication: Option<Communication>,
    pub substations: Vec<Substation>,
    pub lines: Vec<Line>,
    pub processes: Vec<Process>,
    pub ieds: Vec<Ied>,
    pub data_type_templates: Option<DataTypeTemplates>,

    /// Each element name present in the document that this module does not
    /// decode, with the paths it occurs at.
    pub(crate) drops: BTreeMap<String, Vec<String>>,
}

impl Scl {
    /// Returns the named IED, or the first one when `name` is empty.
    pub fn ied(&self, name: &str) -> Option<&Ied> {
        if name.is_empty() {
            return self.ieds.first();
        }
        self.ieds.iter().find(|i| i.name == name)
    }

    /// Returns the SCL edition the document declares. Fields are empty for a
    /// document that states no version.
    pub fn edition(&self) -> Edition {
        Edition {
            namespace: self.xmlns.clone(),
            version: self.version.clone(),
            revision: self.revision.clone(),
            release: self.release.clone(),
        }
    }

    /// Returns the elements present in the document that this module does not
    /// decode, as a mapping from element name to the paths it occurs at.
    ///
    /// A non-empty result is normal and not an error: a vendor private block
    /// and the elements the model does not need are decoded-and-ignored on
    /// purpose. It is reported so a caller that cares about coverage can tell
    /// an intentional omission from an unrecognised construct and, because
    /// dropping an element drops its subtree, see what was lost with it.
    pub fn dropped(&self) -> BTreeMap<String, Vec<String>> {
        self.drops
            .iter()
            .map(|(k, v)| {
                let mut p = v.clone();
                p.sort();
                (k.clone(), p)
            })
            .collect()
    }

    /// Returns the names of the elements this module does not decode, sorted.
    pub fn dropped_names(&self) -> Vec<String> {
        self.drops.keys().cloned().collect()
    }
}

/// The substation section of a system configuration.
///
/// It is decoded so the audit can tell a recognised-but-unused element from
/// an unknown one; it does not contribute to the model of an IED.
#[derive(Debug, Clone, Default)]
pub struct Substation {
    pub name: String,
    pub desc: String,
    pub voltage_levels: Vec<Named>,
    pub functions: Vec<Named>,
    pub conducting: Vec<Named>,
}

/// An element identified only by its name and description: a voltage level,
/// a function, a piece of conducting equipment, a line or a process.
#[derive(Debug, Clone, Default)]
pub struct Named {
    pub name: String,
    pub desc: String,
}

/// A transmission or distribution line.
pub type Line = Named;
/// A process of a system description other than a substation.
pub type Process = Named;

/// Identifies the configuration file.
#[derive(Debug, Clone, Default)]
pub struct Header {
    pub id: String,
    pub version: String,
    pub revision: String,
    pub tool_id: String,
    pub name_structure: String,
    pub text: String,
    /// The revision history (IEC 61850-6, Ed 2.1).
    pub history: Vec<Hitem>,
}

/// One revision history entry.
#[derive(Debug, Clone, Default)]
pub struct Hitem {
    pub version: String,
    pub revision: String,
    pub when: String,
    pub who: String,
    pub what: String,
    pub why: String,
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
    pub desc: String,
    pub kind: String,
    pub bit_rate: Option<DurUnits>,
    pub connected_aps: Vec<ConnectedAp>,
}

/// Binds an IED access point to a subnetwork and carries its addresses and
/// GSE/SMV multicast parameters.
#[derive(Debug, Clone, Default)]
pub struct ConnectedAp {
    pub ied_name: String,
    pub ap_name: String,
    pub desc: String,
    /// The redundancy protocol: none, hsr, prp or rstp.
    pub red_prot: String,
    pub address: Option<Address>,
    pub gses: Vec<Gse>,
    pub smvs: Vec<Smv>,
    pub phys_conns: Vec<PhysConn>,
}

impl ConnectedAp {
    /// Returns the IPv4 address of the access point, if the document declares
    /// one, without any prefix length (`192.168.1.10/24`).
    pub fn ip(&self) -> Option<&str> {
        let s = self.address.as_ref()?.get("IP")?;
        let s = s.split('/').next().unwrap_or(s);
        (!s.is_empty()).then_some(s)
    }
}

/// One physical protocol connection of an access point.
#[derive(Debug, Clone, Default)]
pub struct PhysConn {
    pub kind: String,
    pub address: Option<Address>,
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
    pub desc: String,
    pub address: Option<Address>,
    pub min_time: Option<DurUnits>,
    pub max_time: Option<DurUnits>,
}

/// Carries the multicast address of one sampled-value control block.
#[derive(Debug, Clone, Default)]
pub struct Smv {
    pub ld_inst: String,
    pub cb_name: String,
    pub desc: String,
    pub address: Option<Address>,
    /// The redundancy groups the stream is sent on (IEC 61850-6:2009+AMD2).
    pub lan_redundancy: Vec<LanRedundancy>,
}

/// Binds a sampled-value control block to a redundancy group.
#[derive(Debug, Clone, Default)]
pub struct LanRedundancy {
    pub lan_grp_inst: String,
    pub shm_grp_inst: String,
    pub red_prot: String,
    pub sequencing: String,
    pub time_quality: String,
    pub direction: String,
    pub any_max: Option<DurUnits>,
    pub super_seq_max: Option<DurUnits>,
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
    /// The SCL the IED was originally configured from, which differs from the
    /// document's own when a file has been upgraded (IEC 61850-6, Ed 2.1).
    pub original_scl_version: String,
    pub original_scl_revision: String,
    pub original_scl_release: String,
    /// The Ed 2.1 file-ownership and engineering-rights attributes.
    pub eng_right: String,
    pub owner: String,
    pub eng_revision: String,
    pub services: Option<Services>,
    pub access_points: Vec<AccessPoint>,
    /// The key distribution clients of the IED.
    pub kdc: Vec<Kdc>,
}

/// A key distribution client.
#[derive(Debug, Clone, Default)]
pub struct Kdc {
    pub ied_name: String,
    pub ap_name: String,
    pub ld_inst: String,
    pub ied_type: String,
}

/// One communication access point of an IED.
#[derive(Debug, Clone, Default)]
pub struct AccessPoint {
    pub name: String,
    pub router: bool,
    pub clock: bool,
    pub kdc: bool,
    pub services: Option<Services>,
    pub server: Option<Server>,
    /// The peer access points this one pre-establishes associations with
    /// (IEC 61850-6, Ed 2.1).
    pub server_at: Vec<ServerAt>,
    pub goose_security: Vec<Security>,
    pub smv_security: Vec<Security>,
}

/// A pre-established association with a peer access point.
#[derive(Debug, Clone, Default)]
pub struct ServerAt {
    pub ied_name: String,
    pub ap_name: String,
    pub ld_inst: String,
}

/// A security participant entry of an access point.
#[derive(Debug, Clone, Default)]
pub struct Security {
    pub ied_name: String,
    pub ap_name: String,
    pub ld_inst: String,
    pub subject: String,
    pub issuer_name: String,
    pub serial_number: String,
    pub xfer_number: i32,
}

/// Holds the logical devices visible through an access point.
#[derive(Debug, Clone, Default)]
pub struct Server {
    pub timeout: i32,
    /// The authentication level required of a client: none, password, weak,
    /// strong or certificate (IEC 61850-6, Ed 2.1).
    pub authentication: Option<String>,
    pub associations: Vec<Association>,
    pub l_devices: Vec<LDevice>,
}

/// One pre-established association.
#[derive(Debug, Clone, Default)]
pub struct Association {
    pub ied_name: String,
    pub ld_inst: String,
    pub prefix: String,
    pub ln_class: String,
    pub ln_inst: String,
    pub kind: i32,
    pub association_id: i32,
}

/// One logical device.
#[derive(Debug, Clone, Default)]
pub struct LDevice {
    pub inst: String,
    /// The Ed 2.1 name of the device, which may differ from the MMS domain
    /// name built from `inst`.
    pub ld_name: String,
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
    /// The logs the node holds (IEC 61850-8-1).
    pub logs: Vec<String>,
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
    /// The instance index, used when the data object is an array.
    pub ix: String,
    pub dais: Vec<Dai>,
    pub sdis: Vec<Sdi>,
}

/// Addresses a sub-object or a structured attribute inside a `DOI`.
#[derive(Debug, Clone, Default)]
pub struct Sdi {
    pub name: String,
    pub ix: String,
    pub s_addr: String,
    pub dais: Vec<Dai>,
    pub sdis: Vec<Sdi>,
}

/// An instantiated data attribute with optional values.
#[derive(Debug, Clone, Default)]
pub struct Dai {
    pub name: String,
    pub ix: String,
    /// The sub-address selecting an element of an array, so a `DAI` may target
    /// part of an attribute rather than the whole of it.
    pub s_addr: String,
    pub val_kind: String,
    pub val_import: String,
    pub vals: Vec<Val>,
}

/// An initial value; `s_group` selects the setting group it applies to, and a
/// value without one applies to the active group.
#[derive(Debug, Clone, Default)]
pub struct Val {
    pub s_group: String,
    pub val_kind: String,
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
///
/// `do_name` and `da_name` may carry array index notation, for example
/// `doName="AnIn3" daName="phsA(2).mag.f"`, and `ix` is the alternative Ed 2
/// way of expressing the same thing.
#[derive(Debug, Clone, Default)]
pub struct Fcda {
    pub ld_inst: String,
    pub prefix: String,
    pub ln_class: String,
    pub ln_inst: String,
    pub do_name: String,
    pub da_name: String,
    pub fc: String,
    pub ix: String,
    pub desc: String,
    pub ap_ref: String,
}

/// Declares an IED's or access point's service capabilities.
///
/// The capabilities that change the model are honoured (the report-buffer
/// capacity); the rest are available to a caller that wants to inspect them.
#[derive(Debug, Clone, Default)]
pub struct Services {
    /// The maximum length of the data names the IED supports (32, 64 or 65
    /// per IEC 61850-6). Empty when the document omits it.
    pub name_length: String,
    /// Every capability element present, by name, with its attributes.
    pub capabilities: BTreeMap<String, Vec<(String, String)>>,
    pub conf_report_control: Option<ConfReportControl>,
    pub sup_subscription: Option<SupSubscription>,
}

impl Services {
    /// Reports whether the capability element `name` is present.
    pub fn has(&self, name: &str) -> bool {
        self.capabilities.contains_key(name)
    }
}

/// The report-control capability.
///
/// `max_buf` is how many reports a buffered control block can retain, which
/// the server applies to the blocks that do not configure a depth of their
/// own.
#[derive(Debug, Clone, Default)]
pub struct ConfReportControl {
    pub max: i32,
    pub max_buf: i32,
    /// `unbuffered`, `buffered` or `both`; empty when absent.
    pub buf_mode: String,
    pub buf_conf: String,
}

/// The subscription supervision capability: how many GOOSE and SV
/// subscriptions the IED supervises.
#[derive(Debug, Clone, Copy, Default)]
pub struct SupSubscription {
    pub max_go: i32,
    pub max_sv: i32,
}

/// Configures a buffered or unbuffered report control block.
#[derive(Debug, Clone, Default)]
pub struct ReportControl {
    pub name: String,
    pub desc: String,
    pub rpt_id: String,
    pub dat_set: String,
    /// The Ed 2 database prefix of the dataset.
    pub db_prefix: String,
    pub conf_rev: u32,
    pub buffered: bool,
    pub buf_time: u32,
    pub intg_pd: u32,
    /// The Ed 1 per-block buffer depth, superseded by
    /// `Services/ConfReportControl@maxBuf` in Ed 2.
    pub buf_depth: i32,
    pub trg_ops: Option<TrgOpsElem>,
    pub opt_fields: Option<OptFieldsElem>,
    pub rpt_enabled: Option<RptEnabled>,
    /// The `indexed` attribute; absent means true.
    pub indexed: bool,
}

/// Report and log trigger option flags. `gi` defaults to true in the schema.
#[derive(Debug, Clone, Default)]
pub struct TrgOpsElem {
    pub dchg: bool,
    pub qchg: bool,
    pub dupd: bool,
    pub period: bool,
    pub gi: bool,
}

/// Report optional field flags. `bufOvfl` defaults to true in the schema.
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

/// Limits the number of report control block instances and lists the client
/// logical nodes the block is reserved for.
#[derive(Debug, Clone, Default)]
pub struct RptEnabled {
    pub max: i32,
    pub client_lns: Vec<ClientLn>,
}

/// Reserves a report control block instance for one client logical node, or
/// names a subscriber of a GOOSE or SV control block.
#[derive(Debug, Clone, Default)]
pub struct ClientLn {
    pub ied_name: String,
    pub ap_name: String,
    pub ap_ref: String,
    pub ld_inst: String,
    pub prefix: String,
    pub ln_class: String,
    pub ln_inst: String,
    pub inst_addr: String,
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
    pub db_prefix: String,
    pub conf_rev: u32,
    /// `GOOSE` (the default) or `GSSE`.
    pub kind: String,
    /// Selects the fixed-offset encoding of IEC 61850-8-1, in which every
    /// dataset member has a fixed position and length in the frame. It is a
    /// flag on the control block, not a time.
    pub fixed_offs: bool,
    pub security_enable: String,
    /// The transmission profile, `R-GOOSE` for routable GOOSE.
    pub protocol: Option<Protocol>,
    pub ied_names: Vec<ClientLn>,
}

/// Configures a sampled-value control block.
#[derive(Debug, Clone, Default)]
pub struct SampledValueControl {
    pub name: String,
    pub desc: String,
    pub smv_id: String,
    pub dat_set: String,
    pub db_prefix: String,
    pub conf_rev: u32,
    pub smp_rate: u32,
    pub nof_asdu: u32,
    /// Defaults to true in the schema.
    pub multicast: bool,
    /// `SmpPerPeriod` (the default), `SmpPerSec` or `SecPerSmp`.
    pub smp_mod: String,
    pub sv_type: String,
    pub security_enable: String,
    pub smv_opts: Option<SmvOpts>,
    /// The transmission profile, `R-SV` for routable sampled values.
    pub protocol: Option<Protocol>,
    pub ied_names: Vec<ClientLn>,
}

/// Names the transmission profile of a GOOSE or SV control block.
#[derive(Debug, Clone, Default)]
pub struct Protocol {
    pub value: String,
    pub must_understand: bool,
}

/// Selects the optional fields of the sampled-value ASDU; all default to
/// false in the schema.
#[derive(Debug, Clone, Default)]
pub struct SmvOpts {
    pub refresh_time: bool,
    pub sample_synchronized: bool,
    pub sample_rate: bool,
    pub data_set: bool,
    pub security: bool,
    pub timestamp: bool,
    pub synch_source_id: bool,
}

/// Configures a log control block.
#[derive(Debug, Clone, Default)]
pub struct LogControl {
    pub name: String,
    pub desc: String,
    pub dat_set: String,
    pub db_prefix: String,
    pub log_name: String,
    /// Defaults to true in the schema.
    pub log_ena: bool,
    /// Defaults to true in the schema.
    pub reason_code: bool,
    pub buf_time: u32,
    pub intg_pd: u32,
    /// The logical node holding the log (the Ed 2 addition that lets a log
    /// control name a node other than `LLN0`).
    pub ld_inst: String,
    pub prefix: String,
    pub ln_class: String,
    pub ln_inst: String,
    pub trg_ops: Option<TrgOpsElem>,
}

/// Declares the setting groups of a logical device.
#[derive(Debug, Clone, Copy, Default)]
pub struct SettingControlElem {
    pub num_of_sgs: u8,
    pub act_sg: u8,
    /// How long a reservation lasts, in milliseconds (IEC 61850-8-1, Ed 2.1).
    pub resv_tms: u32,
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
    pub desc: String,
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

/// A logical node type template. Its identity is the pair (`id`,
/// `ln_class`), so two nodes of different classes may share an id.
#[derive(Debug, Clone, Default)]
pub struct LNodeType {
    pub id: String,
    pub ln_class: String,
    pub ied_type: String,
    pub desc: String,
    pub dos: Vec<Do>,
}

/// Declares a data object of a logical node type.
#[derive(Debug, Clone, Default)]
pub struct Do {
    pub name: String,
    pub kind: String,
    pub desc: String,
    pub transient: bool,
}

/// A data object type template, a CDC specialisation.
#[derive(Debug, Clone, Default)]
pub struct DoType {
    pub id: String,
    pub cdc: String,
    pub ied_type: String,
    pub das: Vec<Da>,
    pub sdos: Vec<Sdo>,
}

/// Declares a sub data object inside a `DOType`. `count` makes it an array of
/// that many instances.
#[derive(Debug, Clone, Default)]
pub struct Sdo {
    pub name: String,
    pub kind: String,
    pub desc: String,
    pub count: String,
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
    pub desc: String,
    pub s_addr: String,
    pub val_kind: String,
    pub val_import: String,
    pub vals: Vec<Val>,
}

/// A constructed attribute type template.
#[derive(Debug, Clone, Default)]
pub struct DaType {
    pub id: String,
    pub ied_type: String,
    pub bdas: Vec<Bda>,
}

/// Declares a member of a constructed attribute type.
///
/// It inherits the functional constraint and the trigger options of the `DA`
/// that owns it, so its own trigger attributes are additional to those.
#[derive(Debug, Clone, Default)]
pub struct Bda {
    pub name: String,
    pub btype: String,
    pub kind: String,
    pub count: String,
    pub dchg: bool,
    pub qchg: bool,
    pub dupd: bool,
    pub desc: String,
    pub s_addr: String,
    pub val_kind: String,
    pub val_import: String,
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
    pub desc: String,
    pub name: String,
}
