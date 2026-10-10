//! Sampled-value control blocks as a client sees them (IEC 61850-7-2
//! GetMSVCBValues, GetUSVCBValues and SetUSVCBValues).

use crate::mms::Value;
use crate::model::{Fc, ObjectReference, SmpMod, SvOpts};

use super::{Client, Result};

/// The destination of a GOOSE or sampled-value stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhyComAddr {
    pub addr: [u8; 6],
    pub priority: u8,
    pub vid: u16,
    pub app_id: u16,
}

impl PhyComAddr {
    /// Decodes a PHYCOMADDR structure: Addr, PRIORITY, VID, APPID.
    pub fn from_value(v: &Value) -> PhyComAddr {
        let mut a = PhyComAddr::default();
        let f = v.children();
        if f.len() < 4 {
            return a;
        }
        let b = f[0].bytes();
        let n = b.len().min(6);
        a.addr[..n].copy_from_slice(&b[..n]);
        a.priority = f[1].as_u64() as u8;
        a.vid = f[2].as_u64() as u16;
        a.app_id = f[3].as_u64() as u16;
        a
    }
}

/// A sampled-value control block as a client reads it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Svcb {
    /// `LD/LN.name`.
    pub reference: ObjectReference,
    /// A USVCB (FC US), else an MSVCB (FC MS).
    pub unicast: bool,
    pub sv_ena: bool,
    /// A USVCB's reservation; false for an MSVCB.
    pub resv: bool,
    /// `MsvID` or `UsvID`.
    pub sv_id: String,
    /// The data set reference in MMS notation, `LD/LN$name`.
    pub data_set: String,
    pub conf_rev: u32,
    pub smp_rate: u32,
    pub opt_flds: SvOpts,
    pub smp_mod: SmpMod,
    pub dst_address: PhyComAddr,
    pub no_asdu: u32,
}

impl Client {
    /// Reserves the unicast sampled-value control block at `reference`
    /// (`LD/LLN0.usvcb01`) for this association, or releases it when `on` is
    /// false. While it holds the block no other client may change it; the
    /// server releases it and stops the stream when this association ends.
    pub async fn reserve_usvcb(&self, reference: impl Into<ObjectReference>, on: bool) -> Result<()> {
        self.write(reference.into().child("Resv"), Fc::Us, Value::boolean(on))
            .await
    }

    /// Starts or stops the stream of the sampled-value control block at
    /// `reference`: `SvEna` of an MSVCB (`unicast` false, FC MS) or of a USVCB
    /// (`unicast` true, FC US), which is to be reserved first with
    /// [`reserve_usvcb`](Client::reserve_usvcb) for the stream to be this
    /// client's alone.
    pub async fn enable_svcb(
        &self,
        reference: impl Into<ObjectReference>,
        unicast: bool,
        on: bool,
    ) -> Result<()> {
        let fc = if unicast { Fc::Us } else { Fc::Ms };
        self.write(reference.into().child("SvEna"), fc, Value::boolean(on))
            .await
    }

    /// Reads the sampled-value control block at `reference`
    /// (`LD/LLN0.msvcb01`) in one request.
    ///
    /// Whether it is an MSVCB or a USVCB is found as libiec61850 does: the
    /// block is looked up under FC MS, then US. A component the server does
    /// not serve is left at its zero value.
    pub async fn get_svcb(&self, reference: impl Into<ObjectReference>) -> Result<Svcb> {
        let reference = reference.into();
        let mut cb = Svcb {
            reference: reference.clone(),
            ..Default::default()
        };
        let (mut domain, mut item) = reference.to_mms(Fc::Ms);
        let probe = self
            .mms()
            .read(&domain, &[&format!("{item}$SvEna")])
            .await?;
        if probe.first().and_then(Value::as_access_error).is_some() {
            cb.unicast = true;
            (domain, item) = reference.to_mms(Fc::Us);
        }
        let names: &[&str] = if cb.unicast {
            &["SvEna", "Resv", "UsvID", "DatSet", "ConfRev", "SmpRate", "OptFlds", "SmpMod", "DstAddress", "noASDU"]
        } else {
            &["SvEna", "MsvID", "DatSet", "ConfRev", "SmpRate", "OptFlds", "SmpMod", "DstAddress", "noASDU"]
        };
        let items: Vec<String> = names.iter().map(|n| format!("{item}${n}")).collect();
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        let vals = self.mms().read(&domain, &refs).await?;
        if vals.len() != names.len() {
            return Err(super::Error::Client(format!(
                "{} results for {} components of {reference}",
                vals.len(),
                names.len()
            )));
        }
        if let Some(code) = vals[0].as_access_error() {
            // The block itself is not there.
            return Err(code.into());
        }
        for (name, v) in names.iter().zip(&vals) {
            if v.as_access_error().is_some() {
                continue;
            }
            match *name {
                "SvEna" => cb.sv_ena = v.as_bool(),
                "Resv" => cb.resv = v.as_bool(),
                "MsvID" | "UsvID" => cb.sv_id = v.text(),
                "DatSet" => cb.data_set = v.text(),
                "ConfRev" => cb.conf_rev = v.as_u32(),
                "SmpRate" => cb.smp_rate = v.as_u32(),
                "OptFlds" => {
                    let bit = |i: usize| i < v.bit_len() && v.bit(i);
                    cb.opt_flds = SvOpts {
                        refresh_time: bit(0),
                        sample_synchronized: bit(1),
                        sample_rate: bit(2),
                        data_set: bit(3),
                        security: bit(4),
                        timestamp: bit(5),
                        synch_source_id: bit(6),
                    };
                }
                "SmpMod" => cb.smp_mod = SmpMod::from_code(v.as_i64()),
                "DstAddress" => cb.dst_address = PhyComAddr::from_value(v),
                "noASDU" => cb.no_asdu = v.as_u32(),
                _ => {}
            }
        }
        Ok(cb)
    }
}
