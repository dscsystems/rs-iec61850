//! Turns the generic XML tree into the typed SCL document tree, and audits
//! the document for elements this module does not decode.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use quick_xml::events::Event;
use quick_xml::Reader;

use super::dom::{self, Node};
use super::types::*;
use super::{Error, Result};

/// Decodes an SCL document from a string.
///
/// The root element is checked to be `SCL`, but the document is not validated
/// against the XML schema. The edition the document declares is available
/// from [`Scl::edition`], and the elements this module does not decode from
/// [`Scl::dropped`].
pub fn parse(xml: &str) -> Result<Scl> {
    let root = dom::parse(xml)?;
    if root.name != "SCL" {
        return Err(Error::Xml(format!(
            "root element is <{}>, not <SCL>",
            root.name
        )));
    }
    let mut scl = scl_from(&root);
    scl.drops = audit(xml);
    Ok(scl)
}

/// Decodes an SCL document held in memory as bytes.
pub fn parse_bytes(data: &[u8]) -> Result<Scl> {
    let text = std::str::from_utf8(data)
        .map_err(|e| Error::Xml(format!("document is not UTF-8: {e}")))?;
    parse(text)
}

/// Decodes the SCL document at `path`.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Scl> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)?;
    parse(&text).map_err(|e| match e {
        Error::Xml(msg) => Error::Xml(format!("{}: {msg}", path.display())),
        other => other,
    })
}

/// The SCL element names this module decodes. An element of any other name
/// is recorded by the audit, with the path it sits at.
const DECLARED: &[&str] = &[
    "AccessPoint", "Address", "AnyMax", "Association", "Authentication", "BDA", "BitRate",
    "ClientLN", "ClientServices", "CommProt", "Communication", "ConductingEquipment",
    "ConfDataSet", "ConfLNs", "ConfLogControl", "ConfReportControl", "ConfSG", "ConfSigRef",
    "ConnectedAP", "DA", "DAI", "DataObjectDirectory", "DataSet", "DataSetDirectory",
    "DataTypeTemplates", "DAType", "DO", "DOI", "DOType", "DynAssociation", "EnumType",
    "EnumVal", "ExtRef", "FCDA", "FileHandling", "Function", "GetCBValues",
    "GetDataObjectDefinition", "GetDataSetValue", "GetDirectory", "GOOSE", "GOOSESecurity",
    "GSE", "GSEControl", "GSEDir", "GSESettings", "GSSE", "Header", "History", "Hitem", "IED",
    "IEDName", "Inputs", "IssuerName", "KDC", "LANRedundancy", "LDevice", "Line", "LN", "LN0", "LNodeType",
    "Log", "LogControl", "LogSettings", "MaxTime", "MinTime", "OptFields", "P", "PhysConn",
    "Process", "Protocol", "ReadWrite", "RedProt", "ReportControl", "ReportSettings",
    "RptEnabled", "SampledValueControl", "SCL", "SDI", "SDO", "Server", "ServerAt", "Services",
    "SetDataSetValue", "SettingControl", "SettingGroups", "SGEdit", "SMV", "SmvOpts", "SMVsc",
    "SMVSecurity", "SMVSettings", "SubNetwork", "Subject", "Substation", "SuperSeqMax", "SupSubscription",
    "Text", "TimerActivatedControl", "TimeSyncProt", "TrgOps", "Val", "ValueHandling",
    "VoltageLevel",
];

fn declared() -> &'static BTreeSet<&'static str> {
    static SET: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| DECLARED.iter().copied().collect())
}

/// Bounds the recorded path, so a deeply nested or hostile document cannot
/// make the audit allocate without limit.
const MAX_AUDIT_DEPTH: usize = 32;

/// Walks the document and records the elements this module does not decode,
/// with the path they sit at.
///
/// Dropping an element drops its whole subtree, so the path is what makes a
/// report actionable: `SubNetwork` is noise, `/SCL/Communication/SubNetworks`
/// says the GOOSE addressing of every IED on the network is missing. It
/// streams rather than walking the tree, so arbitrarily deep input costs
/// bounded memory.
fn audit(xml: &str) -> BTreeMap<String, Vec<String>> {
    let mut drops: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut reader = Reader::from_str(xml);
    let mut path: Vec<String> = Vec::new();
    let mut depth = 0usize;
    loop {
        let (name, empty) = match reader.read_event() {
            Ok(Event::Start(e)) => (local_name(e.name().as_ref()), false),
            Ok(Event::Empty(e)) => (local_name(e.name().as_ref()), true),
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
                if depth < path.len() {
                    path.pop();
                }
                continue;
            }
            // Malformed input is reported by the real decode.
            Ok(Event::Eof) | Err(_) => return drops,
            Ok(_) => continue,
        };
        if !declared().contains(name.as_str()) {
            let mut p = format!("/{}", path.iter().chain([&name]).cloned().collect::<Vec<_>>().join("/"));
            if path.len() >= MAX_AUDIT_DEPTH {
                p.push_str("...");
            }
            drops.entry(name.clone()).or_default().push(p);
        }
        if !empty {
            if depth < MAX_AUDIT_DEPTH {
                path.push(name);
            }
            depth += 1;
        }
    }
}

fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => s.into_owned(),
    }
}

fn scl_from(n: &Node) -> Scl {
    Scl {
        xmlns: n.attr_string("xmlns"),
        version: n.attr_string("version"),
        revision: n.attr_string("revision"),
        release: n.attr_string("release"),
        header: n.child("Header").map(header_from).unwrap_or_default(),
        communication: n.child("Communication").map(communication_from),
        substations: n.children_named("Substation").map(substation_from).collect(),
        lines: n.children_named("Line").map(named_from).collect(),
        processes: n.children_named("Process").map(named_from).collect(),
        ieds: n.children_named("IED").map(ied_from).collect(),
        data_type_templates: n.child("DataTypeTemplates").map(templates_from),
        drops: BTreeMap::new(),
    }
}

fn named_from(n: &Node) -> Named {
    Named {
        name: n.attr_string("name"),
        desc: n.attr_string("desc"),
    }
}

fn substation_from(n: &Node) -> Substation {
    Substation {
        name: n.attr_string("name"),
        desc: n.attr_string("desc"),
        voltage_levels: n.children_named("VoltageLevel").map(named_from).collect(),
        functions: n.children_named("Function").map(named_from).collect(),
        conducting: n
            .children_named("ConductingEquipment")
            .map(named_from)
            .collect(),
    }
}

fn header_from(n: &Node) -> Header {
    Header {
        id: n.attr_string("id"),
        version: n.attr_string("version"),
        revision: n.attr_string("revision"),
        tool_id: n.attr_string("toolID"),
        name_structure: n.attr_string("nameStructure"),
        text: n.child("Text").map(|t| t.text.trim().to_string()).unwrap_or_default(),
        history: n
            .child("History")
            .map(|h| {
                h.children_named("Hitem")
                    .map(|i| Hitem {
                        version: i.attr_string("version"),
                        revision: i.attr_string("revision"),
                        when: i.attr_string("when"),
                        who: i.attr_string("who"),
                        what: i.attr_string("what"),
                        why: i.attr_string("why"),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn communication_from(n: &Node) -> Communication {
    Communication {
        sub_networks: n
            .children_named("SubNetwork")
            .map(|s| SubNetwork {
                name: s.attr_string("name"),
                desc: s.attr_string("desc"),
                kind: s.attr_string("type"),
                bit_rate: s.child("BitRate").map(dur_from),
                connected_aps: s.children_named("ConnectedAP").map(connected_ap_from).collect(),
            })
            .collect(),
    }
}

fn connected_ap_from(n: &Node) -> ConnectedAp {
    ConnectedAp {
        ied_name: n.attr_string("iedName"),
        ap_name: n.attr_string("apName"),
        desc: n.attr_string("desc"),
        red_prot: n.attr_string("redProt"),
        address: n.child("Address").map(address_from),
        gses: n
            .children_named("GSE")
            .map(|g| Gse {
                ld_inst: g.attr_string("ldInst"),
                cb_name: g.attr_string("cbName"),
                desc: g.attr_string("desc"),
                address: g.child("Address").map(address_from),
                min_time: g.child("MinTime").map(dur_from),
                max_time: g.child("MaxTime").map(dur_from),
            })
            .collect(),
        smvs: n
            .children_named("SMV")
            .map(|s| Smv {
                ld_inst: s.attr_string("ldInst"),
                cb_name: s.attr_string("cbName"),
                desc: s.attr_string("desc"),
                address: s.child("Address").map(address_from),
                lan_redundancy: s
                    .children_named("LANRedundancy")
                    .map(|l| LanRedundancy {
                        lan_grp_inst: l.attr_string("lanGrpInst"),
                        shm_grp_inst: l.attr_string("shmGrpInst"),
                        red_prot: l.attr_string("redProt"),
                        sequencing: l.attr_string("sequencing"),
                        time_quality: l.attr_string("timeQuality"),
                        direction: l.attr_string("direction"),
                        any_max: l.child("AnyMax").map(dur_from),
                        super_seq_max: l.child("SuperSeqMax").map(dur_from),
                    })
                    .collect(),
            })
            .collect(),
        phys_conns: n
            .children_named("PhysConn")
            .map(|p| PhysConn {
                kind: p.attr_string("type"),
                address: p.child("Address").map(address_from),
            })
            .collect(),
    }
}

fn address_from(n: &Node) -> Address {
    Address {
        ps: n
            .children_named("P")
            .map(|p| P {
                kind: p.attr_string("type"),
                value: p.text.clone(),
            })
            .collect(),
    }
}

fn dur_from(n: &Node) -> DurUnits {
    DurUnits {
        unit: n.attr_string("unit"),
        multiplier: n.attr_string("multiplier"),
        value: n.text.clone(),
    }
}

fn ied_from(n: &Node) -> Ied {
    Ied {
        name: n.attr_string("name"),
        kind: n.attr_string("type"),
        manufacturer: n.attr_string("manufacturer"),
        config_version: n.attr_string("configVersion"),
        original_scl_version: n.attr_string("originalSclVersion"),
        original_scl_revision: n.attr_string("originalSclRevision"),
        original_scl_release: n.attr_string("originalSclRelease"),
        eng_right: n.attr_string("engRight"),
        owner: n.attr_string("owner"),
        eng_revision: n.attr_string("engRevision"),
        services: n.child("Services").map(services_from),
        access_points: n
            .children_named("AccessPoint")
            .map(|a| AccessPoint {
                name: a.attr_string("name"),
                router: a.attr_bool("router", false),
                clock: a.attr_bool("clock", false),
                kdc: a.attr_bool("kdc", false),
                services: a.child("Services").map(services_from),
                server: a.child("Server").map(server_from),
                server_at: a
                    .children_named("ServerAt")
                    .map(|s| ServerAt {
                        ied_name: s.attr_string("iedName"),
                        ap_name: s.attr_string("apName"),
                        ld_inst: s.attr_string("ldInst"),
                    })
                    .collect(),
                goose_security: a.children_named("GOOSESecurity").map(security_from).collect(),
                smv_security: a.children_named("SMVSecurity").map(security_from).collect(),
            })
            .collect(),
        kdc: n
            .children_named("KDC")
            .map(|k| Kdc {
                ied_name: k.attr_string("iedName"),
                ap_name: k.attr_string("apName"),
                ld_inst: k.attr_string("ldInst"),
                ied_type: k.attr_string("iedType"),
            })
            .collect(),
    }
}

fn security_from(n: &Node) -> Security {
    // Subject and IssuerName are elements of a certificate (tCert), carrying
    // their name in commonName or as text depending on the tool.
    let cert_name = |name: &str| {
        n.child(name)
            .map(|c| match c.attr("commonName") {
                Some(cn) => cn.to_string(),
                None => c.text.trim().to_string(),
            })
            .unwrap_or_default()
    };
    Security {
        ied_name: n.attr_string("iedName"),
        ap_name: n.attr_string("apName"),
        ld_inst: n.attr_string("ldInst"),
        subject: cert_name("Subject"),
        issuer_name: cert_name("IssuerName"),
        serial_number: n.attr_string("serialNumber"),
        xfer_number: n.attr_num("xferNumber"),
    }
}

fn services_from(n: &Node) -> Services {
    Services {
        name_length: n.attr_string("nameLength"),
        capabilities: n
            .children
            .iter()
            .map(|c| (c.name.clone(), c.attrs.clone()))
            .collect(),
        conf_report_control: n.child("ConfReportControl").map(|c| ConfReportControl {
            max: c.attr_num("max"),
            max_buf: c.attr_num("maxBuf"),
            buf_mode: c.attr_string("bufMode"),
            buf_conf: c.attr_string("bufConf"),
        }),
        sup_subscription: n.child("SupSubscription").map(|s| SupSubscription {
            max_go: s.attr_num("maxGo"),
            max_sv: s.attr_num("maxSv"),
        }),
    }
}

fn server_from(n: &Node) -> Server {
    Server {
        timeout: n.attr_num("timeout"),
        authentication: n.child("Authentication").map(|a| a.text.trim().to_string()),
        associations: n
            .children_named("Association")
            .map(|a| Association {
                ied_name: a.attr_string("iedName"),
                ld_inst: a.attr_string("ldInst"),
                prefix: a.attr_string("prefix"),
                ln_class: a.attr_string("lnClass"),
                ln_inst: a.attr_string("lnInst"),
                kind: a.attr_num("kind"),
                association_id: a.attr_num("associationID"),
            })
            .collect(),
        l_devices: n
            .children_named("LDevice")
            .map(|d| LDevice {
                inst: d.attr_string("inst"),
                ld_name: d.attr_string("ldName"),
                ln0: d.child("LN0").map(ln_from),
                lns: d.children_named("LN").map(ln_from).collect(),
            })
            .collect(),
    }
}

fn client_ln_from(n: &Node) -> ClientLn {
    ClientLn {
        ied_name: n.attr_string("iedName"),
        ap_name: n.attr_string("apName"),
        ap_ref: n.attr_string("apRef"),
        ld_inst: n.attr_string("ldInst"),
        prefix: n.attr_string("prefix"),
        ln_class: n.attr_string("lnClass"),
        ln_inst: n.attr_string("lnInst"),
        inst_addr: n.attr_string("instAddr"),
    }
}

fn protocol_from(n: &Node) -> Protocol {
    Protocol {
        value: n.text.clone(),
        must_understand: n.attr_bool("mustUnderstand", false),
    }
}

fn ln_from(n: &Node) -> Ln {
    Ln {
        // LN0 carries no lnClass attribute in some tools' output; the element
        // name is authoritative there.
        ln_class: match n.attr("lnClass") {
            Some(c) if !c.is_empty() => c.to_string(),
            _ if n.name == "LN0" => "LLN0".to_string(),
            _ => String::new(),
        },
        inst: n.attr_string("inst"),
        ln_type: n.attr_string("lnType"),
        prefix: n.attr_string("prefix"),
        dois: n.children_named("DOI").map(doi_from).collect(),
        data_sets: n.children_named("DataSet").map(data_set_from).collect(),
        report_controls: n
            .children_named("ReportControl")
            .map(report_control_from)
            .collect(),
        gse_controls: n
            .children_named("GSEControl")
            .map(|g| GseControl {
                name: g.attr_string("name"),
                desc: g.attr_string("desc"),
                app_id: g.attr_string("appID"),
                dat_set: g.attr_string("datSet"),
                db_prefix: g.attr_string("dbprefix"),
                conf_rev: g.attr_num("confRev"),
                kind: g.attr_string("type"),
                fixed_offs: g.attr_bool("fixedOffs", false),
                security_enable: g.attr_string("securityEnable"),
                protocol: g.child("Protocol").map(protocol_from),
                ied_names: g.children_named("IEDName").map(client_ln_from).collect(),
            })
            .collect(),
        sampled_value_controls: n
            .children_named("SampledValueControl")
            .map(|s| SampledValueControl {
                name: s.attr_string("name"),
                desc: s.attr_string("desc"),
                smv_id: s.attr_string("smvID"),
                dat_set: s.attr_string("datSet"),
                db_prefix: s.attr_string("dbprefix"),
                conf_rev: s.attr_num("confRev"),
                smp_rate: s.attr_num("smpRate"),
                nof_asdu: s.attr_num("nofASDU"),
                multicast: s.attr_bool("multicast", true),
                smp_mod: s.attr_string("smpMod"),
                sv_type: s.attr_string("svType"),
                security_enable: s.attr_string("securityEnable"),
                smv_opts: s.child("SmvOpts").map(|o| SmvOpts {
                    refresh_time: o.attr_bool("refreshTime", false),
                    sample_synchronized: o.attr_bool("sampleSynchronized", false),
                    sample_rate: o.attr_bool("sampleRate", false),
                    data_set: o.attr_bool("dataSet", false),
                    security: o.attr_bool("security", false),
                    timestamp: o.attr_bool("timestamp", false),
                    synch_source_id: o.attr_bool("synchSourceId", false),
                }),
                protocol: s.child("Protocol").map(protocol_from),
                ied_names: s.children_named("IEDName").map(client_ln_from).collect(),
            })
            .collect(),
        log_controls: n
            .children_named("LogControl")
            .map(|l| LogControl {
                name: l.attr_string("name"),
                desc: l.attr_string("desc"),
                dat_set: l.attr_string("datSet"),
                db_prefix: l.attr_string("dbprefix"),
                log_name: l.attr_string("logName"),
                log_ena: l.attr_bool("logEna", true),
                reason_code: l.attr_bool("reasonCode", true),
                buf_time: l.attr_num("bufTime"),
                intg_pd: l.attr_num("intgPd"),
                ld_inst: l.attr_string("ldInst"),
                prefix: l.attr_string("prefix"),
                ln_class: l.attr_string("lnClass"),
                ln_inst: l.attr_string("lnInst"),
                trg_ops: l.child("TrgOps").map(trg_ops_from),
            })
            .collect(),
        setting_control: n.child("SettingControl").map(|s| SettingControlElem {
            num_of_sgs: s.attr_num("numOfSGs"),
            act_sg: s.attr_num("actSG"),
            resv_tms: s.attr_num("resvTms"),
        }),
        inputs: n.child("Inputs").map(|i| Inputs {
            ext_refs: i.children_named("ExtRef").map(ext_ref_from).collect(),
        }),
        logs: n
            .children_named("Log")
            .filter_map(|l| {
                let name = l.attr_or_empty("name").trim();
                (!name.is_empty()).then(|| name.to_string())
            })
            .collect(),
    }
}

fn ext_ref_from(n: &Node) -> ExtRef {
    ExtRef {
        ied_name: n.attr_string("iedName"),
        ld_inst: n.attr_string("ldInst"),
        prefix: n.attr_string("prefix"),
        ln_class: n.attr_string("lnClass"),
        ln_inst: n.attr_string("lnInst"),
        do_name: n.attr_string("doName"),
        da_name: n.attr_string("daName"),
        int_addr: n.attr_string("intAddr"),
        desc: n.attr_string("desc"),
        service_type: n.attr_string("serviceType"),
        src_ld_inst: n.attr_string("srcLDInst"),
        src_prefix: n.attr_string("srcPrefix"),
        src_ln_class: n.attr_string("srcLNClass"),
        src_ln_inst: n.attr_string("srcLNInst"),
        src_cb_name: n.attr_string("srcCBName"),
    }
}

fn doi_from(n: &Node) -> Doi {
    Doi {
        name: n.attr_string("name"),
        ix: n.attr_string("ix"),
        dais: n.children_named("DAI").map(dai_from).collect(),
        sdis: n.children_named("SDI").map(sdi_from).collect(),
    }
}

fn sdi_from(n: &Node) -> Sdi {
    Sdi {
        name: n.attr_string("name"),
        ix: n.attr_string("ix"),
        s_addr: n.attr_string("sAddr"),
        dais: n.children_named("DAI").map(dai_from).collect(),
        sdis: n.children_named("SDI").map(sdi_from).collect(),
    }
}

fn dai_from(n: &Node) -> Dai {
    Dai {
        name: n.attr_string("name"),
        ix: n.attr_string("ix"),
        s_addr: n.attr_string("sAddr"),
        val_kind: n.attr_string("valKind"),
        val_import: n.attr_string("valImport"),
        vals: n.children_named("Val").map(val_from).collect(),
    }
}

fn val_from(n: &Node) -> Val {
    Val {
        s_group: n.attr_string("sGroup"),
        val_kind: n.attr_string("valKind"),
        value: n.text.clone(),
    }
}

fn data_set_from(n: &Node) -> DataSet {
    DataSet {
        name: n.attr_string("name"),
        desc: n.attr_string("desc"),
        fcdas: n
            .children_named("FCDA")
            .map(|f| Fcda {
                ld_inst: f.attr_string("ldInst"),
                prefix: f.attr_string("prefix"),
                ln_class: f.attr_string("lnClass"),
                ln_inst: f.attr_string("lnInst"),
                do_name: f.attr_string("doName"),
                da_name: f.attr_string("daName"),
                fc: f.attr_string("fc"),
                ix: f.attr_string("ix"),
                desc: f.attr_string("desc"),
                ap_ref: f.attr_string("apRef"),
            })
            .collect(),
    }
}

fn report_control_from(n: &Node) -> ReportControl {
    ReportControl {
        name: n.attr_string("name"),
        desc: n.attr_string("desc"),
        rpt_id: n.attr_string("rptID"),
        dat_set: n.attr_string("datSet"),
        db_prefix: n.attr_string("dbprefix"),
        conf_rev: n.attr_num("confRev"),
        buffered: n.attr_bool("buffered", false),
        buf_time: n.attr_num("bufTime"),
        intg_pd: n.attr_num("intgPd"),
        buf_depth: n.attr_num("bufDepth"),
        indexed: n.attr_bool("indexed", true),
        trg_ops: n.child("TrgOps").map(trg_ops_from),
        opt_fields: n.child("OptFields").map(|o| OptFieldsElem {
            seq_num: o.attr_bool("seqNum", false),
            time_stamp: o.attr_bool("timeStamp", false),
            data_set: o.attr_bool("dataSet", false),
            reason_code: o.attr_bool("reasonCode", false),
            data_ref: o.attr_bool("dataRef", false),
            entry_id: o.attr_bool("entryID", false),
            config_ref: o.attr_bool("configRef", false),
            // bufOvfl defaults to true in the schema.
            buf_ovfl: o.attr_bool("bufOvfl", true),
            segmentation: o.attr_bool("segmentation", false),
        }),
        rpt_enabled: n.child("RptEnabled").map(|r| RptEnabled {
            max: r.attr_num("max"),
            client_lns: r.children_named("ClientLN").map(client_ln_from).collect(),
        }),
    }
}

fn trg_ops_from(n: &Node) -> TrgOpsElem {
    TrgOpsElem {
        dchg: n.attr_bool("dchg", false),
        qchg: n.attr_bool("qchg", false),
        dupd: n.attr_bool("dupd", false),
        period: n.attr_bool("period", false),
        // Per the schema, gi defaults to true.
        gi: n.attr_bool("gi", true),
    }
}

fn templates_from(n: &Node) -> DataTypeTemplates {
    DataTypeTemplates {
        ln_node_types: n
            .children_named("LNodeType")
            .map(|t| LNodeType {
                id: t.attr_string("id"),
                ln_class: t.attr_string("lnClass"),
                ied_type: t.attr_string("iedType"),
                desc: t.attr_string("desc"),
                dos: t
                    .children_named("DO")
                    .map(|d| Do {
                        name: d.attr_string("name"),
                        kind: d.attr_string("type"),
                        desc: d.attr_string("desc"),
                        transient: d.attr_bool("transient", false),
                    })
                    .collect(),
            })
            .collect(),
        do_types: n
            .children_named("DOType")
            .map(|t| DoType {
                id: t.attr_string("id"),
                cdc: t.attr_string("cdc"),
                ied_type: t.attr_string("iedType"),
                das: t.children_named("DA").map(da_from).collect(),
                sdos: t
                    .children_named("SDO")
                    .map(|s| Sdo {
                        name: s.attr_string("name"),
                        kind: s.attr_string("type"),
                        desc: s.attr_string("desc"),
                        count: s.attr_string("count"),
                    })
                    .collect(),
            })
            .collect(),
        da_types: n
            .children_named("DAType")
            .map(|t| DaType {
                id: t.attr_string("id"),
                ied_type: t.attr_string("iedType"),
                bdas: t
                    .children_named("BDA")
                    .map(|b| Bda {
                        name: b.attr_string("name"),
                        btype: b.attr_string("bType"),
                        kind: b.attr_string("type"),
                        count: b.attr_string("count"),
                        dchg: b.attr_bool("dchg", false),
                        qchg: b.attr_bool("qchg", false),
                        dupd: b.attr_bool("dupd", false),
                        desc: b.attr_string("desc"),
                        s_addr: b.attr_string("sAddr"),
                        val_kind: b.attr_string("valKind"),
                        val_import: b.attr_string("valImport"),
                        vals: b.children_named("Val").map(val_from).collect(),
                    })
                    .collect(),
            })
            .collect(),
        enum_types: n
            .children_named("EnumType")
            .map(|t| EnumType {
                id: t.attr_string("id"),
                enum_vals: t
                    .children_named("EnumVal")
                    .map(|v| EnumVal {
                        ord: v.attr_num("ord"),
                        desc: v.attr_string("desc"),
                        name: v.text.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn da_from(n: &Node) -> Da {
    Da {
        name: n.attr_string("name"),
        fc: n.attr_string("fc"),
        btype: n.attr_string("bType"),
        kind: n.attr_string("type"),
        count: n.attr_string("count"),
        dchg: n.attr_bool("dchg", false),
        qchg: n.attr_bool("qchg", false),
        dupd: n.attr_bool("dupd", false),
        desc: n.attr_string("desc"),
        s_addr: n.attr_string("sAddr"),
        val_kind: n.attr_string("valKind"),
        val_import: n.attr_string("valImport"),
        vals: n.children_named("Val").map(val_from).collect(),
    }
}
