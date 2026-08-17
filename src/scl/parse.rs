//! Turns the generic XML tree into the typed SCL document tree.

use std::path::Path;

use super::dom::{self, Node};
use super::types::*;
use super::{Error, Result};

/// Decodes an SCL document from a string.
///
/// The root element is checked to be `SCL`, but the document is not validated
/// against the XML schema.
pub fn parse(xml: &str) -> Result<Scl> {
    let root = dom::parse(xml)?;
    if root.name != "SCL" {
        return Err(Error::Xml(format!(
            "root element is <{}>, not <SCL>",
            root.name
        )));
    }
    Ok(scl_from(&root))
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

fn scl_from(n: &Node) -> Scl {
    Scl {
        version: n.attr_string("version"),
        revision: n.attr_string("revision"),
        header: n.child("Header").map(header_from).unwrap_or_default(),
        communication: n.child("Communication").map(communication_from),
        ieds: n.children_named("IED").map(ied_from).collect(),
        data_type_templates: n.child("DataTypeTemplates").map(templates_from),
    }
}

fn header_from(n: &Node) -> Header {
    Header {
        id: n.attr_string("id"),
        version: n.attr_string("version"),
        revision: n.attr_string("revision"),
        tool_id: n.attr_string("toolID"),
    }
}

fn communication_from(n: &Node) -> Communication {
    Communication {
        sub_networks: n
            .children_named("SubNetwork")
            .map(|s| SubNetwork {
                name: s.attr_string("name"),
                kind: s.attr_string("type"),
                connected_aps: s.children_named("ConnectedAP").map(connected_ap_from).collect(),
            })
            .collect(),
    }
}

fn connected_ap_from(n: &Node) -> ConnectedAp {
    ConnectedAp {
        ied_name: n.attr_string("iedName"),
        ap_name: n.attr_string("apName"),
        address: n.child("Address").map(address_from),
        gses: n
            .children_named("GSE")
            .map(|g| Gse {
                ld_inst: g.attr_string("ldInst"),
                cb_name: g.attr_string("cbName"),
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
                address: s.child("Address").map(address_from),
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
        services: n.child("Services").map(services_from),
        access_points: n
            .children_named("AccessPoint")
            .map(|a| AccessPoint {
                name: a.attr_string("name"),
                services: a.child("Services").map(services_from),
                server: a.child("Server").map(server_from),
            })
            .collect(),
    }
}

fn services_from(n: &Node) -> Services {
    Services {
        conf_report_control: n.child("ConfReportControl").map(|c| ConfReportControl {
            max: c.attr_num("max"),
            max_buf: c.attr_num("maxBuf"),
        }),
    }
}

fn server_from(n: &Node) -> Server {
    Server {
        l_devices: n
            .children_named("LDevice")
            .map(|d| LDevice {
                inst: d.attr_string("inst"),
                ln0: d.child("LN0").map(ln_from),
                lns: d.children_named("LN").map(ln_from).collect(),
            })
            .collect(),
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
                conf_rev: g.attr_num("confRev"),
                kind: g.attr_string("type"),
            })
            .collect(),
        sampled_value_controls: n
            .children_named("SampledValueControl")
            .map(|s| SampledValueControl {
                name: s.attr_string("name"),
                smv_id: s.attr_string("smvID"),
                dat_set: s.attr_string("datSet"),
                conf_rev: s.attr_num("confRev"),
                smp_rate: s.attr_num("smpRate"),
                nof_asdu: s.attr_num("nofASDU"),
                multicast: s.attr_bool("multicast", true),
            })
            .collect(),
        log_controls: n
            .children_named("LogControl")
            .map(|l| LogControl {
                name: l.attr_string("name"),
                dat_set: l.attr_string("datSet"),
                log_name: l.attr_string("logName"),
                log_ena: l.attr_bool("logEna", true),
                intg_pd: l.attr_num("intgPd"),
                trg_ops: l.child("TrgOps").map(trg_ops_from),
            })
            .collect(),
        setting_control: n.child("SettingControl").map(|s| SettingControlElem {
            num_of_sgs: s.attr_num("numOfSGs"),
            act_sg: s.attr_num("actSG"),
        }),
        inputs: n.child("Inputs").map(|i| Inputs {
            ext_refs: i.children_named("ExtRef").map(ext_ref_from).collect(),
        }),
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
        dais: n.children_named("DAI").map(dai_from).collect(),
        sdis: n.children_named("SDI").map(sdi_from).collect(),
    }
}

fn sdi_from(n: &Node) -> Sdi {
    Sdi {
        name: n.attr_string("name"),
        dais: n.children_named("DAI").map(dai_from).collect(),
        sdis: n.children_named("SDI").map(sdi_from).collect(),
    }
}

fn dai_from(n: &Node) -> Dai {
    Dai {
        name: n.attr_string("name"),
        vals: n.children_named("Val").map(val_from).collect(),
    }
}

fn val_from(n: &Node) -> Val {
    Val {
        s_group: n.attr_string("sGroup"),
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
        conf_rev: n.attr_num("confRev"),
        buffered: n.attr_bool("buffered", false),
        buf_time: n.attr_num("bufTime"),
        intg_pd: n.attr_num("intgPd"),
        trg_ops: n.child("TrgOps").map(trg_ops_from),
        opt_fields: n.child("OptFields").map(|o| OptFieldsElem {
            seq_num: o.attr_bool("seqNum", false),
            time_stamp: o.attr_bool("timeStamp", false),
            data_set: o.attr_bool("dataSet", false),
            reason_code: o.attr_bool("reasonCode", false),
            data_ref: o.attr_bool("dataRef", false),
            entry_id: o.attr_bool("entryID", false),
            config_ref: o.attr_bool("configRef", false),
            buf_ovfl: o.attr_bool("bufOvfl", false),
            segmentation: o.attr_bool("segmentation", false),
        }),
        rpt_enabled: n.child("RptEnabled").map(|r| RptEnabled {
            max: r.attr_num("max"),
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
                dos: t
                    .children_named("DO")
                    .map(|d| Do {
                        name: d.attr_string("name"),
                        kind: d.attr_string("type"),
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
                das: t.children_named("DA").map(da_from).collect(),
                sdos: t
                    .children_named("SDO")
                    .map(|s| Sdo {
                        name: s.attr_string("name"),
                        kind: s.attr_string("type"),
                    })
                    .collect(),
            })
            .collect(),
        da_types: n
            .children_named("DAType")
            .map(|t| DaType {
                id: t.attr_string("id"),
                bdas: t
                    .children_named("BDA")
                    .map(|b| Bda {
                        name: b.attr_string("name"),
                        btype: b.attr_string("bType"),
                        kind: b.attr_string("type"),
                        count: b.attr_string("count"),
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
        vals: n.children_named("Val").map(val_from).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
<SCL version="2007" revision="B">
  <Header id="demo" toolID="test"/>
  <Communication>
    <SubNetwork name="W01" type="8-MMS">
      <ConnectedAP iedName="ied1" apName="S1">
        <Address><P type="IP">10.0.0.1</P></Address>
        <GSE ldInst="LD0" cbName="gcb01">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-01</P>
            <P type="APPID">1000</P>
            <P type="VLAN-ID">003</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="ied1" manufacturer="DSC">
    <Services><ConfReportControl max="8" maxBuf="512"/></Services>
    <AccessPoint name="S1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_1">
            <DataSet name="Events">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <ReportControl name="EventsRCB" rptID="rpt" datSet="Events" confRev="1"
                           buffered="true" bufTime="50" intgPd="60000">
              <TrgOps dchg="true" qchg="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true"/>
              <RptEnabled max="2"/>
            </ReportControl>
            <GSEControl name="gcb01" appID="events" datSet="Events" confRev="1"/>
            <SettingControl numOfSGs="4" actSG="1"/>
          </LN0>
          <LN prefix="" lnClass="GGIO" inst="1" lnType="GGIO_1">
            <DOI name="Ind1">
              <DAI name="stVal"><Val>true</Val></DAI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_1" lnClass="LLN0"><DO name="Mod" type="INC_1"/></LNodeType>
    <LNodeType id="GGIO_1" lnClass="GGIO"><DO name="Ind1" type="SPS_1"/></LNodeType>
    <DOType id="SPS_1" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <DOType id="INC_1" cdc="INC">
      <DA name="stVal" bType="Enum" type="Mod_e" fc="ST" dchg="true"/>
    </DOType>
    <EnumType id="Mod_e">
      <EnumVal ord="1">on</EnumVal>
      <EnumVal ord="2">blocked</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>"#;

    #[test]
    fn a_document_parses_into_its_typed_tree() {
        let s = parse(MINIMAL).unwrap();
        assert_eq!(s.version, "2007");
        assert_eq!(s.header.id, "demo");
        assert_eq!(s.ieds.len(), 1);
        assert_eq!(s.ieds[0].name, "ied1");
        assert_eq!(s.ieds[0].manufacturer, "DSC");
        let ap = &s.ieds[0].access_points[0];
        assert_eq!(ap.name, "S1");
        let ld = &ap.server.as_ref().unwrap().l_devices[0];
        assert_eq!(ld.inst, "LD0");
        assert_eq!(ld.all_lns().count(), 2, "LN0 plus one LN");
        assert_eq!(ld.ln0.as_ref().unwrap().instance_name(), "LLN0");
        assert_eq!(ld.lns[0].instance_name(), "GGIO1");
    }

    #[test]
    fn a_root_element_that_is_not_scl_is_rejected() {
        assert!(parse("<NotSCL/>").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn control_blocks_and_datasets_are_decoded() {
        let s = parse(MINIMAL).unwrap();
        let ln0 = s.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .l_devices[0]
            .ln0
            .as_ref()
            .unwrap();

        assert_eq!(ln0.data_sets[0].name, "Events");
        assert_eq!(ln0.data_sets[0].fcdas[0].do_name, "Ind1");
        assert_eq!(ln0.data_sets[0].fcdas[0].fc, "ST");

        let rc = &ln0.report_controls[0];
        assert_eq!(rc.name, "EventsRCB");
        assert!(rc.buffered);
        assert_eq!(rc.buf_time, 50);
        assert_eq!(rc.intg_pd, 60000);
        assert_eq!(rc.rpt_enabled.unwrap().max, 2);
        let t = rc.trg_ops.as_ref().unwrap();
        assert!(t.dchg && t.qchg && !t.dupd && !t.period);
        assert!(t.gi, "gi defaults to true when the attribute is absent");
        let o = rc.opt_fields.as_ref().unwrap();
        assert!(o.seq_num && o.time_stamp && o.data_set && o.reason_code);
        assert!(!o.entry_id);

        assert_eq!(ln0.gse_controls[0].app_id, "events");
        assert_eq!(ln0.setting_control.unwrap().num_of_sgs, 4);
    }

    #[test]
    fn the_communication_section_is_decoded_with_its_addresses() {
        let s = parse(MINIMAL).unwrap();
        let comm = s.communication.as_ref().unwrap();
        let ap = &comm.sub_networks[0].connected_aps[0];
        assert_eq!(ap.ied_name, "ied1");
        assert_eq!(ap.address.as_ref().unwrap().get("IP"), Some("10.0.0.1"));

        let gse = &ap.gses[0];
        assert_eq!(gse.cb_name, "gcb01");
        let addr = gse.address.as_ref().unwrap();
        assert_eq!(addr.get("MAC-Address"), Some("01-0C-CD-01-00-01"));
        assert_eq!(addr.get("APPID"), Some("1000"));
        assert_eq!(gse.min_time.as_ref().unwrap().millis(), 4);
        assert_eq!(gse.max_time.as_ref().unwrap().millis(), 1000);
    }

    #[test]
    fn data_type_templates_are_decoded() {
        let s = parse(MINIMAL).unwrap();
        let t = s.data_type_templates.as_ref().unwrap();
        assert_eq!(t.ln_node_types.len(), 2);
        assert_eq!(t.do_types.len(), 2);
        let sps = t.do_types.iter().find(|d| d.id == "SPS_1").unwrap();
        assert_eq!(sps.cdc, "SPS");
        assert_eq!(sps.das.len(), 3);
        assert!(sps.das[0].dchg, "stVal is a data-change trigger");
        assert!(sps.das[1].qchg, "q is a quality-change trigger");

        let e = &t.enum_types[0];
        assert_eq!(e.ord_of("on"), Some(1));
        assert_eq!(e.ord_of("blocked"), Some(2));
        assert_eq!(e.ord_of("nope"), None);
    }

    #[test]
    fn initial_values_are_decoded() {
        let s = parse(MINIMAL).unwrap();
        let ggio = &s.ieds[0].access_points[0]
            .server
            .as_ref()
            .unwrap()
            .l_devices[0]
            .lns[0];
        assert_eq!(ggio.dois[0].name, "Ind1");
        assert_eq!(ggio.dois[0].dais[0].name, "stVal");
        assert_eq!(ggio.dois[0].dais[0].vals[0].value, "true");
    }

    #[test]
    fn the_named_ied_is_selected_and_an_unknown_one_is_not() {
        let s = parse(MINIMAL).unwrap();
        assert_eq!(s.ied("ied1").map(|i| i.name.as_str()), Some("ied1"));
        assert_eq!(s.ied("").map(|i| i.name.as_str()), Some("ied1"));
        assert!(s.ied("nope").is_none());
    }
}
