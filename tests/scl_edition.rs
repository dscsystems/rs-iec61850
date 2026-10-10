//! Edition 2.1 (SCL 2007B4) loading: edition detection, the audit of
//! undecoded elements, permissive loading with diagnostics, array instances,
//! setting groups and the Ed 2.1 control block fields.
//!
//! `testdata/ed21_diverse.cid` is a synthetic 2007B4 CID exercising the
//! constructs an Ed 1 or Ed 2.0 file usually does not use.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use iec61850::mms::Type;
use iec61850::model::{self, Fc, Model};
use iec61850::scl::{self, BuildOptions, Scl};

const ED21: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/ed21_diverse.cid");
const SIMPLE_IO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid");

fn load_ed21() -> (Scl, Model) {
    let s = scl::parse_file(ED21).expect("parse");
    let m = scl::build_model(&s, &BuildOptions::new()).expect("build");
    (s, m)
}

fn load(doc: &str) -> Model {
    let s = scl::parse(doc).expect("parse");
    scl::build_model(&s, &BuildOptions::new()).expect("build")
}

fn assert_diagnostic(m: &Model, substr: &str) {
    if m.diagnostics.iter().any(|d| d.message.contains(substr)) {
        return;
    }
    let all: Vec<String> = m.diagnostics.iter().map(ToString::to_string).collect();
    panic!("no diagnostic containing {substr:?}; got:\n  {}", all.join("\n  "));
}

fn node<'m>(m: &'m Model, ld: &str, ln: &str) -> &'m model::LogicalNode {
    m.device(ld).unwrap().node(ln).unwrap()
}

#[test]
fn the_edition_is_detected() {
    let (s, _) = load_ed21();
    let e = s.edition();
    assert!(e.known(), "{e} reported as not known");
    assert_eq!(e.to_string(), "2007B4");
    assert!(e.at_least_ed2() && !e.is_ed1());
}

/// The Ed 1 fixture declares no version at all, which the schema permits; it
/// loads as before rather than being reported as an unknown edition.
#[test]
fn an_absent_edition_is_not_an_error() {
    let s = scl::parse_file(SIMPLE_IO).unwrap();
    assert_eq!(s.edition().version, "");
    scl::build_model(&s, &BuildOptions::new()).unwrap();
}

#[test]
fn an_unknown_edition_is_reported() {
    let doc = r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2099" revision="Z" release="9">
      <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0"/></Server></AccessPoint></IED>
    </SCL>"#;
    let s = scl::parse(doc).unwrap();
    assert!(!s.edition().known());
    let err = scl::build_model(&s, &BuildOptions::new().strict(true)).unwrap_err();
    assert!(err.to_string().contains("2099"), "{err}");
}

/// A vendor namespace is not an error either: elements are matched by local
/// name, so the document still parses and the namespace is reported.
#[test]
fn a_vendor_namespace_is_reported() {
    let doc = r#"<SCL xmlns="http://example.com/scl" version="2007" revision="B" release="4">
      <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0"/></Server></AccessPoint></IED>
    </SCL>"#;
    let s = scl::parse(doc).unwrap();
    assert!(scl::build_model(&s, &BuildOptions::new().strict(true)).is_err());
    assert!(scl::build_model(&s, &BuildOptions::new()).is_ok());
}

/// An unrecognised element takes its whole subtree with it, so the audit
/// reports where it was rather than only its name.
#[test]
fn a_dropped_element_reports_its_path() {
    let doc = r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
      <Communication><SubNetworks name="x"><ConnectedAP iedName="I" apName="A"/></SubNetworks></Communication>
    </SCL>"#;
    let s = scl::parse(doc).unwrap();
    let dropped = s.dropped();
    let paths = dropped.get("SubNetworks").expect("SubNetworks reported");
    assert!(paths[0].contains("/SCL/Communication/SubNetworks"), "{paths:?}");
    assert!(scl::build_model(&s, &BuildOptions::new().strict(true)).is_err());
}

/// A known-but-unused element is not reported as unknown, or the audit would
/// be noise.
#[test]
fn the_fixture_drops_nothing() {
    let (s, _) = load_ed21();
    assert!(s.dropped_names().is_empty(), "{:?}", s.dropped_names());
}

/// An unknown basic type keeps the attribute in the tree: the object stays
/// browsable and the datasets that name it still resolve.
#[test]
fn an_unknown_basic_type_loads() {
    let (_, m) = load_ed21();
    let vendor = node(&m, "ED21LD0", "GGIO1").object("VendorDO").expect("VendorDO");
    let st_val = vendor.attribute("stVal").expect("VendorDO.stVal");
    assert!(st_val.value.is_none(), "{:?}", st_val.value);
    assert_diagnostic(&m, r#"basic type "VendorType7""#);
}

/// The two Ed 2.1 option bit strings are real types and are served.
#[test]
fn the_ed21_option_bit_strings_are_ten_bits() {
    let (_, m) = load_ed21();
    let vendor = node(&m, "ED21LD0", "GGIO1").object("VendorDO").unwrap();
    for name in ["opts", "lgOpts"] {
        let da = vendor.attribute(name).expect(name);
        assert_eq!(da.value.as_ref().expect(name).bit_len(), 10, "{name}");
    }
}

/// PhyComAddr is the physical communication address of Ed 2. IEC 61850-8-1
/// maps it to the structure a GoCB's DstAddress is served as.
#[test]
fn phy_com_addr_loads_as_a_structure() {
    let (_, m) = load_ed21();
    let phy = node(&m, "ED21LD0", "PHC1").object("PhyCom").expect("PhyCom");
    let da = phy.attribute("PhyComAddr").expect("PhyComAddr");
    assert_eq!(da.kind, Some(Type::Structure));
    for (name, kind) in [
        ("Addr", Type::OctetString),
        ("PRIORITY", Type::Unsigned),
        ("VID", Type::Unsigned),
        ("APPID", Type::Unsigned),
    ] {
        let c = da.child(name).expect(name);
        assert_eq!((c.kind, c.fc), (Some(kind), Fc::Cf), "{name}");
        assert!(c.value.is_some(), "{name}");
    }
    assert_eq!(da.child("Addr").unwrap().value.as_ref().unwrap().bytes().len(), 6);
}

/// An SDO with a count becomes that many instances, named so that the
/// references a dataset spells with array notation resolve.
#[test]
fn an_array_sub_object_has_one_instance_per_element() {
    let (_, mut m) = load_ed21();
    let an_in3 = m
        .device_mut("ED21LD0")
        .unwrap()
        .node_mut("GGIO1")
        .unwrap()
        .object_mut("AnIn3")
        .unwrap();
    assert_eq!(an_in3.objects.len(), 5);
    for (i, sub) in an_in3.objects.iter().enumerate() {
        assert_eq!(sub.name, format!("phsA({})", i + 1));
    }
    // The instances have independent values.
    an_in3.objects[0]
        .attribute_mut("mag")
        .unwrap()
        .child_mut("f")
        .unwrap()
        .value = Some(iec61850::mms::Value::float32(1.0));
    let f2 = an_in3.objects[1].attribute("mag").unwrap().child("f").unwrap();
    assert_eq!(f2.value.as_ref().unwrap().as_f32(), 0.0);
}

/// An unknown functional constraint is carried verbatim, so the object stays
/// visible and the item ID uses the mnemonic the document used.
#[test]
fn an_unknown_functional_constraint_is_carried() {
    let (_, m) = load_ed21();
    let beh = node(&m, "ED21LD0", "GGIO1").object("Beh").unwrap();
    let da = beh.attribute("vendorFCAttr").expect("vendorFCAttr");
    assert_eq!(da.fc, Fc::Unknown);
    assert_eq!(model::fc_text(da.fc, &da.fc_name), "ZX");
    assert_eq!(beh.fc_text(da.fc), "ZX");
    assert_diagnostic(&m, r#"functional constraint "ZX""#);
}

/// FCDA@ix and array notation both name the member of an array, and a member
/// under an unknown constraint is kept with its mnemonic.
#[test]
fn dataset_members_name_array_elements() {
    let (_, m) = load_ed21();
    let ds = node(&m, "ED21LD0", "LLN0").data_set("Measurements").expect("Measurements");
    let got: Vec<&str> = ds.entries.iter().map(|e| e.reference.as_str()).collect();
    assert_eq!(
        got,
        [
            "ED21LD0/MMXU1.TotW.mag.f",
            "ED21LD0/GGIO1.AnIn3.phsA(2).mag.f",
            "ED21LD0/GGIO1.AnIn1.phsAngRef(2)",
            "ED21LD0/GGIO1.AnIn1.mag.f",
        ]
    );
    let last = ds.entries.last().unwrap();
    assert_eq!(last.fc, Fc::Unknown);
    assert_eq!(last.fc_text(), "ZX");
}

/// Val@sGroup gives a distinct value per setting group, and the device serves
/// the group its SettingControl declares active.
#[test]
fn setting_groups_are_recorded_and_the_active_one_served() {
    let (_, m) = load_ed21();
    assert_eq!(m.setting_groups.len(), 2);
    let g = &m.setting_groups[0];
    assert_eq!((g.number, g.ld.as_str()), (1, "ED21LD0"));
    assert_eq!(g.values["ED21LD0/GGIO1.IntRange.setVal"].as_f32(), 50.5);
    assert_eq!(g.values["ED21LD0/GGIO1.IntRange.setMag.f"].as_f32(), -1.5);
    assert_eq!(m.setting_groups[1].values["ED21LD0/GGIO1.IntRange.setVal"].as_f32(), 60.5);
    // actSG="1", so the object carries group 1's values.
    let ir = node(&m, "ED21LD0", "GGIO1").object("IntRange").unwrap();
    assert_eq!(ir.attribute("setVal").unwrap().value.as_ref().unwrap().as_f32(), 50.5);
    let f = ir.attribute("setMag").unwrap().child("f").unwrap();
    assert_eq!(f.value.as_ref().unwrap().as_f32(), -1.5);
}

/// A DAI sAddr addresses one element of an array attribute.
#[test]
fn a_dai_s_addr_sets_one_element() {
    let (_, m) = load_ed21();
    let mag = node(&m, "ED21LD0", "GGIO1")
        .object("AnIn1")
        .unwrap()
        .attribute("mag")
        .unwrap();
    let arr = mag.child("phsAngRef").expect("phsAngRef");
    assert_eq!(arr.count, 3);
    assert_eq!(arr.elem(0).unwrap().as_f32(), 11.5);
    assert_eq!(arr.elem(1).unwrap().as_f32(), 22.5);
    assert_eq!(arr.elem(2).unwrap().as_f32(), 0.0);
    assert_eq!(mag.child("f").unwrap().value.as_ref().unwrap().as_f32(), 33.5);
}

/// An SDI ix addresses an element of an array-valued sub-object.
#[test]
fn an_sdi_ix_addresses_one_instance() {
    let (_, m) = load_ed21();
    let an_in3 = node(&m, "ED21LD0", "GGIO1").object("AnIn3").unwrap();
    let f = |i: usize| {
        an_in3.objects[i].attribute("mag").unwrap().child("f").unwrap().value.as_ref().unwrap().as_f32()
    };
    assert_eq!(f(2), 99.5);
    assert_eq!(f(0), 0.0);
}

#[test]
fn sampled_value_control_blocks_carry_their_ed21_fields() {
    let (_, m) = load_ed21();
    let ln = node(&m, "ED21LD0", "LLN0");
    assert_eq!(ln.sv_controls.len(), 2);
    let by = |n: &str| ln.sv_controls.iter().find(|s| s.name == n).unwrap();
    let mcast = by("msvcb01");
    assert_eq!(mcast.smp_mod, model::SmpMod::SmpPerSec);
    assert!(mcast.multicast);
    assert_eq!(mcast.sv_type, "MSV");
    assert!(mcast.opts.sample_synchronized && mcast.opts.synch_source_id);
    assert!(!mcast.opts.data_set && !mcast.opts.security);
    let ucast = by("usvcb01");
    assert!(!ucast.multicast);
    assert_eq!(ucast.sv_type, "");
    assert_eq!(ucast.protocol, "R-SV");
    assert!(ucast.opts.data_set && ucast.opts.security);
}

/// A GSSE control block is told apart from a GOOSE one, R-GOOSE is carried
/// as the block's protocol, and fixedOffs is carried and reported.
#[test]
fn goose_control_block_variants() {
    let (_, m) = load_ed21();
    let ln = node(&m, "ED21LD0", "LLN0");
    let by = |n: &str| ln.gse_controls.iter().find(|g| g.name == n).unwrap();
    assert_eq!(by("gcb01").kind, model::GsType::Goose);
    assert_eq!(by("gcb01").protocol, "R-GOOSE");
    assert_eq!(by("gscb01").kind, model::GsType::Gsse);
    assert!(by("gcb01").fixed_offs && !by("gscb01").fixed_offs);
    assert_diagnostic(&m, "fixed-offset");
    assert_diagnostic(&m, "GSSE");
}

#[test]
fn goose_timing_comes_from_the_communication_section() {
    let (_, m) = load_ed21();
    let gc = node(&m, "ED21LD0", "LLN0")
        .gse_controls
        .iter()
        .find(|g| g.name == "gcb01")
        .unwrap();
    assert_eq!((gc.min_time, gc.max_time), (20, 1000));
    assert_eq!(gc.dst_mac, [1, 0x0c, 0xcd, 3, 0, 1]);
    assert_eq!(gc.app_id, 0x2000);
}

#[test]
fn log_control_fields() {
    let (_, m) = load_ed21();
    let lcs = &node(&m, "ED21LD0", "LLN0").log_controls;
    assert_eq!(lcs.len(), 1);
    let lc = &lcs[0];
    assert!(lc.log_ena && lc.reason_code);
    assert_eq!(lc.buf_time, 500);
}

#[test]
fn the_setting_control_carries_resv_tms() {
    let (_, m) = load_ed21();
    let sc = node(&m, "ED21LD0", "LLN0").setting_control.unwrap();
    assert_eq!((sc.num_of_sgs, sc.act_sg, sc.resv_tms), (2, 1, 30000));
}

/// bufOvfl defaults to true in the schema, so an OptFields element that does
/// not mention it still requests it.
#[test]
fn buf_ovfl_defaults_to_true() {
    let (_, m) = load_ed21();
    let rc = node(&m, "ED21LD0", "LLN0").report_control("brcb01").unwrap();
    assert!(rc.opt_flds.has(model::OptFlds::BUF_OVFL));
    assert!(!rc.opt_flds.has(model::OptFlds::SEGMENTATION));
    assert!(rc.opt_flds.has(model::OptFlds::ENTRY_ID));
}

/// RptEnabled beyond the 99 two-digit instance names is capped and reported.
#[test]
fn rpt_enabled_is_capped() {
    let m = load(
        r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
      <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0T">
          <ReportControl name="urcb" rptID="r" confRev="1" buffered="false">
            <RptEnabled max="1000"/>
          </ReportControl>
        </LN0>
      </LDevice></Server></AccessPoint></IED>
      <DataTypeTemplates>
        <LNodeType id="LLN0T" lnClass="LLN0"><DO name="Mod" type="INC"/></LNodeType>
        <DOType id="INC" cdc="INC"><DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/></DOType>
      </DataTypeTemplates>
    </SCL>"#,
    );
    assert_eq!(node(&m, "ILD0", "LLN0").report_controls[0].rpt_enabled, 99);
    assert_diagnostic(&m, "capped");
}

/// The count a document asks for is bounded, so a corrupt or hostile value
/// cannot make the loader allocate without limit.
#[test]
fn an_array_count_is_bounded() {
    let m = load(
        r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
      <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0T"/>
      </LDevice></Server></AccessPoint></IED>
      <DataTypeTemplates>
        <LNodeType id="LLN0T" lnClass="LLN0"><DO name="AnIn3" type="WYE"/></LNodeType>
        <DOType id="WYE" cdc="WYE"><SDO name="phsA" type="CMV" count="200000000"/></DOType>
        <DOType id="CMV" cdc="CMV"><DA name="mag" bType="FLOAT32" fc="MX" dchg="true"/></DOType>
      </DataTypeTemplates>
    </SCL>"#,
    );
    assert!(node(&m, "ILD0", "LLN0").object("AnIn3").unwrap().objects.is_empty());
}

/// Strict turns the collected diagnostics into an error; the permissive build
/// returns the same model, and on_warn streams the same diagnostics.
#[test]
fn strict_and_on_warn() {
    let s = scl::parse_file(ED21).unwrap();
    let permissive = scl::build_model(&s, &BuildOptions::new()).unwrap();
    assert!(!permissive.diagnostics.is_empty());
    match scl::build_model(&s, &BuildOptions::new().strict(true)) {
        Err(scl::Error::Strict { diagnostics, .. }) => {
            assert_eq!(diagnostics.len(), permissive.diagnostics.len())
        }
        other => panic!("strict build: {other:?}"),
    }
    let seen = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&seen);
    let m = scl::build_model(
        &s,
        &BuildOptions::new().on_warn(move |_| *counter.lock().unwrap() += 1),
    )
    .unwrap();
    assert_eq!(*seen.lock().unwrap(), m.diagnostics.len());
}

/// A corrupt or truncated document is still a hard error: permissiveness is
/// about unrecognised constructs, not about malformed XML.
#[test]
fn a_malformed_document_fails() {
    for doc in [r#"<SCL><IED name="I""#, "<NotSCL/>", ""] {
        assert!(scl::parse(doc).is_err(), "{doc:?}");
    }
}

/// A LNodeType is identified by (id, lnClass), so a document that reuses an
/// id across node classes resolves each to its own template.
#[test]
fn an_ln_node_type_is_identified_by_id_and_class() {
    let (_, m) = load_ed21();
    let ggio1 = node(&m, "ED21LD0", "GGIO1");
    assert!(ggio1.object("AnIn1").is_some());
    assert!(ggio1.object("AnIn9").is_none());
}

/// The audit does not blow up on deeply nested input, and bounds the paths
/// it records.
#[test]
fn the_audit_is_depth_bounded() {
    let mut doc = String::from(
        r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4"><Unknown>"#,
    );
    doc.push_str(&"<Unknown>".repeat(5000));
    doc.push_str(&"</Unknown>".repeat(5000));
    doc.push_str("</Unknown></SCL>");
    let s = scl::parse(&doc).unwrap();
    let dropped = s.dropped();
    let paths = dropped.get("Unknown").expect("reported");
    assert!(!paths.is_empty());
    assert!(paths.iter().all(|p| p.len() <= 1 << 10));
}

/// A ClientLN reserves the instance at its position for the client IED it
/// names, identified by the IP address of that IED's access point.
#[test]
fn client_ln_reservations() {
    let (_, m) = load_ed21();
    let ln = node(&m, "ED21LD0", "LLN0");
    let urcb = ln.report_control("urcb01").unwrap();
    let brcb = ln.report_control("brcb01").unwrap();
    let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
    assert_eq!(urcb.reservations.len(), 1);
    assert_eq!(urcb.reservations[0].as_ref().unwrap().ip, ip("192.168.1.11"));
    assert_eq!(brcb.reservations.len(), 2);
    let r = brcb.reservations[0].as_ref().unwrap();
    assert_eq!((r.ied_name.as_str(), r.ip), ("HMI", ip("10.0.0.50")));
    assert!(brcb.reservations[1].is_none());
    assert_diagnostic(&m, r#""GHOST""#);
}

/// A routable control block's destination is the IP address of its GSE or
/// SMV address.
#[test]
fn routable_destinations() {
    let (_, m) = load_ed21();
    let lln0 = node(&m, "ED21LD0", "LLN0");
    let gcb = lln0.gse_controls.iter().find(|g| g.name == "gcb01").unwrap();
    assert_eq!(gcb.protocol, "R-GOOSE");
    assert_eq!(gcb.dst_ip, Some("239.192.0.1".parse().unwrap()));
    let usv = lln0.sv_controls.iter().find(|s| s.name == "usvcb01").unwrap();
    assert_eq!(usv.dst_ip, Some("2001:db8::10".parse().unwrap()));
    let msv = lln0.sv_controls.iter().find(|s| s.name == "msvcb01").unwrap();
    assert!(msv.dst_ip.is_none());
    // A routable block is reported only when it cannot be sent routably.
    assert!(!m
        .diagnostics
        .iter()
        .any(|d| d.message.contains("R-GOOSE") || d.message.contains("R-SV")));
    let raw = std::fs::read_to_string(ED21).unwrap();
    let no_ip = raw.replacen(r#"<P type="IP">239.192.0.1</P>"#, "", 1);
    assert_diagnostic(&load(&no_ip), "Protocol is R-GOOSE but the GSE address has no IP");
}

const TWO_LD_HEADER: &str = r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0">
      <LN0 lnClass="LLN0" inst="" lnType="LLN0T">
        <SettingControl numOfSGs="2" actSG="2"/>"#;

/// A setting-group value belongs to the logical device that declares it.
#[test]
fn setting_groups_do_not_leak_between_logical_devices() {
    let doc = format!(
        r#"{TWO_LD_HEADER}
        <DOI name="IntRange"><DAI name="setVal"><Val sGroup="2">111</Val></DAI></DOI>
      </LN0>
      <LN lnClass="GGIO" inst="1" lnType="GGT">
        <DOI name="IntRange"><DAI name="setVal"><Val sGroup="2">222</Val></DAI></DOI>
      </LN>
    </LDevice>
    <LDevice inst="LD1">
      <LN0 lnClass="LLN0" inst="" lnType="LLN0T"><SettingControl numOfSGs="2" actSG="2"/></LN0>
      <LN lnClass="GGIO" inst="1" lnType="GGT">
        <DOI name="IntRange"><DAI name="setVal"><Val sGroup="2">333</Val></DAI></DOI>
      </LN>
    </LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="IntRange" type="ASGT"/></LNodeType>
    <LNodeType id="GGT" lnClass="GGIO"><DO name="IntRange" type="ASGT"/></LNodeType>
    <DOType id="ASGT" cdc="ASG"><DA name="setVal" bType="FLOAT32" fc="SG" dchg="true"/></DOType>
  </DataTypeTemplates>
</SCL>"#
    );
    let m = load(&doc);
    for (ln, ld, want) in [("GGIO1", "ILD0", 222.0), ("LLN0", "ILD0", 111.0), ("GGIO1", "ILD1", 333.0)] {
        let v = node(&m, ld, ln).object("IntRange").unwrap().attribute("setVal").unwrap();
        assert_eq!(v.value.as_ref().unwrap().as_f32(), want, "{ld}/{ln}");
    }
    assert_eq!(m.setting_groups.len(), 2);
    let g0 = m.setting_groups.iter().find(|g| g.ld == "ILD0").unwrap();
    assert_eq!(g0.values.len(), 2);
    assert_eq!(g0.values["ILD0/GGIO1.IntRange.setVal"].as_f32(), 222.0);
    assert_eq!(g0.values["ILD0/LLN0.IntRange.setVal"].as_f32(), 111.0);
    let g1 = m.setting_groups.iter().find(|g| g.ld == "ILD1").unwrap();
    assert_eq!(g1.values.len(), 1);
    assert_eq!(g1.values["ILD1/GGIO1.IntRange.setVal"].as_f32(), 333.0);
}

/// An enum-typed attribute inside a multi-instance data object resolves a Val
/// given as a literal name.
#[test]
fn the_enum_binding_survives_array_cloning() {
    let m = load(
        r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <DOI name="AnIn3"><SDI name="phsA" ix="2"><DAI name="dirGeneral"><Val>forward</Val></DAI></SDI></DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="AnIn3" type="ACDC"/></LNodeType>
    <DOType id="ACDC" cdc="ACD"><SDO name="phsA" type="ACDT" count="3"/></DOType>
    <DOType id="ACDT" cdc="ACD">
      <DA name="general" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="dirGeneral" bType="Enum" type="Dir" fc="ST" dchg="true"/>
    </DOType>
    <EnumType id="Dir"><EnumVal ord="1">forward</EnumVal><EnumVal ord="2">backward</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#,
    );
    let an_in3 = node(&m, "ILD0", "LLN0").object("AnIn3").unwrap();
    assert_eq!(an_in3.objects.len(), 3);
    for (i, sub) in an_in3.objects.iter().enumerate() {
        let want = if i == 1 { 1 } else { 0 };
        let v = sub.attribute("dirGeneral").unwrap().value.as_ref().unwrap().as_i64();
        assert_eq!(v, want, "phsA({})", i + 1);
    }
}

/// A DAI sAddr addressing an element of an array of Enums resolves the
/// literal too.
#[test]
fn the_enum_binding_survives_an_s_addr_element() {
    let m = load(
        r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <DOI name="AnIn1"><DAI name="dirs" sAddr="2"><Val>backward</Val></DAI></DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="AnIn1" type="MVT"/></LNodeType>
    <DOType id="MVT" cdc="MV"><DA name="dirs" bType="Enum" type="Dir" fc="MX" dchg="true" count="3"/></DOType>
    <EnumType id="Dir"><EnumVal ord="1">forward</EnumVal><EnumVal ord="2">backward</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#,
    );
    let dirs = node(&m, "ILD0", "LLN0").object("AnIn1").unwrap().attribute("dirs").unwrap();
    assert_eq!(dirs.elem(1).unwrap().as_i64(), 2);
    assert_eq!(dirs.elem(0).unwrap().as_i64(), 0);
}

/// A Val with both an sAddr and an sGroup other than the active one defines
/// that group and not the active group.
#[test]
fn an_s_addr_with_a_setting_group_is_recorded_not_leaked() {
    let m = load(
        r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <SettingControl numOfSGs="2" actSG="1"/>
      <DOI name="IntRange"><DAI name="setVals" sAddr="1"><Val sGroup="2">42.5</Val></DAI></DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="IntRange" type="ASGT"/></LNodeType>
    <DOType id="ASGT" cdc="ASG"><DA name="setVals" bType="FLOAT32" fc="SG" dchg="true" count="3"/></DOType>
  </DataTypeTemplates>
</SCL>"#,
    );
    let set_vals = node(&m, "ILD0", "LLN0").object("IntRange").unwrap().attribute("setVals").unwrap();
    assert_eq!(set_vals.elem(0).unwrap().as_f32(), 0.0, "the group-2 value leaked");
    let g = m.setting_groups.iter().find(|g| g.number == 2).expect("group 2 recorded");
    let arr = &g.values["ILD0/LLN0.IntRange.setVals"];
    assert_eq!(arr.type_of(), Type::Array);
    assert_eq!(arr.index(0).unwrap().as_f32(), 42.5);
}

/// A Val with sGroup on an attribute that is not a setting-group attribute is
/// still applied, and recorded as nothing.
#[test]
fn only_sg_and_se_values_are_recorded_as_setting_groups() {
    let m = load(
        r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <SettingControl numOfSGs="2" actSG="2"/>
      <DOI name="SPS"><DAI name="stVal"><Val sGroup="2">true</Val></DAI></DOI>
      <DOI name="IntRange"><DAI name="setVal"><Val sGroup="2">7.5</Val></DAI></DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="SPS" type="SPST"/><DO name="IntRange" type="ASGT"/></LNodeType>
    <DOType id="SPST" cdc="SPS"><DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/></DOType>
    <DOType id="ASGT" cdc="ASG"><DA name="setVal" bType="FLOAT32" fc="SG" dchg="true"/></DOType>
  </DataTypeTemplates>
</SCL>"#,
    );
    let ln = node(&m, "ILD0", "LLN0");
    assert!(ln.object("SPS").unwrap().attribute("stVal").unwrap().value.as_ref().unwrap().as_bool());
    for g in &m.setting_groups {
        assert!(!g.values.contains_key("ILD0/LLN0.SPS.stVal"));
        assert_eq!(g.values["ILD0/LLN0.IntRange.setVal"].as_f32(), 7.5);
    }
}

/// A loaded model can be checked against the 7-4 logical node classes. The
/// synthetic fixture breaks 7-4 in known ways; the check finds exactly those,
/// and the loader itself reports none of them.
#[test]
fn the_7_4_check_on_the_fixtures() {
    let (_, m) = load_ed21();
    let got: Vec<String> = m.check_ln_classes().iter().map(ToString::to_string).collect();
    assert_eq!(
        got,
        [
            "ED21LD0/LLN0: mandatory data object NamPlt (LPL) of LLN0 is missing",
            "ED21LD0/MMXU1: mandatory data object Beh (ENS) of MMXU is missing",
            "ED21LD0/GGIO1.AnIn3: data object of class WYE, IEC 61850-7-4 gives GGIO.AnIn the class MV",
            "ED21LD0/GAPC1: mandatory data object Beh (ENS) of GAPC is missing",
            "ED21LD0/LTRK1: mandatory data object Beh (ENS) of LTRK is missing",
            "ED21LD0/GGIO2.AnIn3: data object of class WYE, IEC 61850-7-4 gives GGIO.AnIn the class MV",
        ]
    );
    for d in &m.diagnostics {
        assert!(
            !d.message.contains("7-4") && !d.message.contains("mandatory data object"),
            "the loader reported a 7-4 finding: {d}"
        );
    }
    let m2 = scl::load_model(SIMPLE_IO, &BuildOptions::new()).unwrap();
    assert!(m2.check_ln_classes().is_empty(), "{:?}", m2.check_ln_classes());
}

/// The Edition 2 and 2.1 classes of the fixture are shaped as IEC 61850-7-3
/// defines them, so what the loader builds from the file and what
/// `new_data_object` builds from its template agree.
#[test]
fn ed2_classes_match_their_templates() {
    let (_, m) = load_ed21();
    let ld = m.device("ED21LD0").unwrap();
    for ln_name in ["GAPC1", "LTRK1"] {
        let ln = ld.node(ln_name).unwrap();
        for o in &ln.objects {
            let path = format!("{ln_name}.{}", o.name);
            let cdc = model::Cdc::from_name(&o.cdc)
                .unwrap_or_else(|| panic!("{path}: class {:?} has no template", o.cdc));
            for d in &m.diagnostics {
                assert!(
                    !(d.path.contains(&path) && d.message.contains("attribute templates")),
                    "{path} reported as an unknown class: {d}"
                );
            }
            let (shape, names) = template_options(o);
            let tmpl = model::new_data_object(&o.name, cdc, &shape.clone().with_optional(names));
            compare_to_template(&path, &o.attributes, &tmpl.attributes);
            for want in model::new_data_object(&o.name, cdc, &shape).attributes {
                assert!(
                    o.attribute(&want.name).is_some(),
                    "{path}.{}: mandatory in 7-3, missing from the file",
                    want.name
                );
            }
        }
    }
    let cur = ld.node("GAPC1").unwrap().object("Cur").unwrap().attribute("cur").unwrap();
    assert_eq!(cur.value.as_ref().unwrap().text(), "EUR");
}

/// Asks the template for what the loaded object has: the length of its
/// arrays and a control model when it is controllable, and its optional
/// attributes at any depth.
fn template_options(o: &model::DataObject) -> (model::CdcOptions, Vec<String>) {
    fn collect(das: &[model::DataAttribute], out: &mut Vec<String>) {
        for da in das {
            out.push(da.name.clone());
            collect(&da.children, out);
        }
    }
    let mut names = Vec::new();
    collect(&o.attributes, &mut names);
    let mut shape = model::CdcOptions::new();
    for da in &o.attributes {
        if da.kind == Some(Type::Array) && da.count > 0 {
            shape = shape.with_max_pts(da.count);
        }
        if da.name == "Oper" {
            shape = shape
                .with_control_model(model::CtlModel::DirectNormal)
                .without_cancel();
        }
    }
    (shape, names)
}

fn compare_to_template(path: &str, got: &[model::DataAttribute], want: &[model::DataAttribute]) {
    // MMS structures are positional: within one functional constraint the
    // members the file has must come in the template's order.
    let mut last: std::collections::HashMap<Fc, usize> = Default::default();
    for g in got {
        if let Some(i) = want.iter().position(|w| w.name == g.name) {
            if let Some(l) = last.get(&g.fc) {
                assert!(i >= *l, "{path}.{}: out of the 7-3 order", g.name);
            }
            last.insert(g.fc, i);
        }
    }
    for g in got {
        let p = format!("{path}.{}", g.name);
        let w = want
            .iter()
            .find(|w| w.name == g.name)
            .unwrap_or_else(|| panic!("{p}: in the file, not in the 7-3 template"));
        assert_eq!(g.fc, w.fc, "{p}");
        assert_eq!(g.kind, w.kind, "{p}");
        if g.kind == Some(Type::Array) {
            assert_eq!(g.count, w.count, "{p}");
        }
        if let (Some(gv), Some(wv)) = (&g.value, &w.value) {
            if g.kind == Some(Type::BitString) {
                assert_eq!(gv.bit_len(), wv.bit_len(), "{p}");
            }
        }
        compare_to_template(&p, &g.children, &w.children);
    }
}

/// The service tracking model libiec61850 ships with its
/// `server_example_service_tracking`, an Edition 2 LTRK written independently
/// of this crate, matches the templates here. Set `IEC61850_LIBIEC_LTRK_ICD`
/// to its `simpleIO_ltrk_tests.icd` to run it.
#[test]
fn libiec61850_service_tracking_model_matches_the_templates() {
    let Ok(path) = std::env::var("IEC61850_LIBIEC_LTRK_ICD") else {
        eprintln!("skipped: set IEC61850_LIBIEC_LTRK_ICD");
        return;
    };
    let m = scl::load_model(&path, &BuildOptions::new()).unwrap();
    let ltrk = m
        .devices
        .iter()
        .flat_map(|ld| &ld.nodes)
        .find(|ln| ln.class == "LTRK")
        .expect("no LTRK in the model");
    assert!(m.check_ln_classes().is_empty(), "{:?}", m.check_ln_classes());
    for o in &ltrk.objects {
        let cdc = model::Cdc::from_name(&o.cdc)
            .unwrap_or_else(|| panic!("{}: class {:?} has no template", o.name, o.cdc));
        let (mut shape, names) = template_options(o);
        match o.name.as_str() {
            "IncTrk" => shape = shape.with_tracked_control(model::Cdc::Inc),
            "BscTrk" => shape = shape.with_tracked_control(model::Cdc::Bsc),
            _ => {}
        }
        // The description and namespace attributes are general to every class
        // and not in the tables.
        let got: Vec<model::DataAttribute> = o
            .attributes
            .iter()
            .filter(|a| !matches!(a.name.as_str(), "dU" | "cdcNs" | "cdcName" | "dataNs"))
            .cloned()
            .collect();
        let tmpl = model::new_data_object(&o.name, cdc, &shape.clone().with_optional(names));
        compare_to_template(&format!("LTRK.{}", o.name), &got, &tmpl.attributes);
        for want in model::new_data_object(&o.name, cdc, &shape).attributes {
            assert!(
                o.attribute(&want.name).is_some(),
                "LTRK.{}.{}: mandatory here, not in libiec61850's model",
                o.name,
                want.name
            );
        }
    }
}
