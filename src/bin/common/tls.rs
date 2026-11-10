//! TLS credential options shared by the bundled tools.
#[derive(Debug, Clone, Default)]
pub struct TlsArgs {
    pub cert: Option<String>,
    pub key: Option<String>,
    pub ca: Option<String>,
    pub crl: Option<String>,
    pub server_name: Option<String>,
    pub no_server_name: bool,
    pub tls13: bool,
    pub mms_cert: Option<String>,
    pub mms_key: Option<String>,
    pub mms_ca: Vec<std::path::PathBuf>,
    pub mms_crl: Vec<std::path::PathBuf>,
    pub mms_without_tls: bool,
    pub mms_legacy: bool,
    pub e2e_cert: Option<String>,
    pub e2e_key: Option<String>,
    pub e2e_ca: Vec<std::path::PathBuf>,
    pub e2e_crl: Vec<std::path::PathBuf>,
    pub e2e_path: Vec<std::path::PathBuf>,
    pub e2e_peer: Option<String>,
    pub e2e_edition: Option<String>,
    pub e2e_icv: Option<String>,
    pub e2e_group: Option<String>,
}

impl TlsArgs {
    pub fn parse(
        &mut self,
        flag: &str,
        args: &mut impl Iterator<Item = String>,
    ) -> Result<bool, String> {
        match flag {
            "--e2e-ca" | "--e2e-crl" | "--e2e-path" => {
                let path = args
                    .next()
                    .ok_or_else(|| format!("{flag} requires a value"))?
                    .into();
                match flag {
                    "--e2e-ca" => self.e2e_ca.push(path),
                    "--e2e-crl" => self.e2e_crl.push(path),
                    _ => self.e2e_path.push(path),
                }
                return Ok(true);
            }
            "--mms-ca" | "--mms-crl" => {
                let path = args
                    .next()
                    .ok_or_else(|| format!("{flag} requires a value"))?
                    .into();
                if flag == "--mms-ca" {
                    self.mms_ca.push(path);
                } else {
                    self.mms_crl.push(path);
                }
                return Ok(true);
            }
            "--mms-without-tls" => {
                self.mms_without_tls = true;
                return Ok(true);
            }
            "--mms-legacy-mechanism" => {
                self.mms_legacy = true;
                return Ok(true);
            }
            _ => {}
        }
        let target = match flag {
            "--e2e-cert" => &mut self.e2e_cert,
            "--e2e-key" => &mut self.e2e_key,
            "--e2e-peer" => &mut self.e2e_peer,
            "--e2e-edition" => &mut self.e2e_edition,
            "--e2e-icv" => &mut self.e2e_icv,
            "--e2e-group" => &mut self.e2e_group,
            "--mms-cert" => &mut self.mms_cert,
            "--mms-key" => &mut self.mms_key,
            "--tls-cert" => &mut self.cert,
            "--tls-key" => &mut self.key,
            "--tls-ca" => &mut self.ca,
            "--tls-crl" => &mut self.crl,
            "--tls-server-name" => &mut self.server_name,
            "--tls-no-server-name" => {
                self.no_server_name = true;
                return Ok(true);
            }
            "--tls13" => {
                self.tls13 = true;
                return Ok(true);
            }
            _ => return Ok(false),
        };
        *target = Some(
            args.next()
                .ok_or_else(|| format!("{flag} requires a value"))?,
        );
        Ok(true)
    }
    pub fn enabled(&self) -> bool {
        self.cert.is_some()
            || self.key.is_some()
            || self.ca.is_some()
            || self.crl.is_some()
            || self.server_name.is_some()
            || self.no_server_name
            || self.tls13
    }

    fn a_profile_enabled(&self) -> bool {
        self.mms_cert.is_some()
            || self.mms_key.is_some()
            || !self.mms_ca.is_empty()
            || !self.mms_crl.is_empty()
            || self.mms_without_tls
            || self.mms_legacy
    }

    fn e2e_enabled(&self) -> bool {
        self.e2e_cert.is_some()
            || self.e2e_key.is_some()
            || !self.e2e_ca.is_empty()
            || !self.e2e_crl.is_empty()
            || !self.e2e_path.is_empty()
            || self.e2e_peer.is_some()
            || self.e2e_edition.is_some()
            || self.e2e_icv.is_some()
            || self.e2e_group.is_some()
    }
    #[allow(dead_code)]
    pub fn application_security_enabled(&self) -> bool {
        self.a_profile_enabled() || self.e2e_enabled()
    }
    #[cfg(feature = "e2e")]
    fn e2e(
        &self,
    ) -> Result<std::sync::Arc<iec61850::iec62351::e2e::Config>, Box<dyn std::error::Error>> {
        use iec61850::iec62351::{
            e2e::{self, Edition, Group, IcvAlgorithm},
            pki::UnavailablePolicy,
        };
        if self.a_profile_enabled() {
            return Err("E2E cannot be combined with A-profile".into());
        }
        let mut config = e2e::Files {
            certificate: self
                .e2e_cert
                .as_ref()
                .ok_or("--e2e-cert is required")?
                .into(),
            key: self.e2e_key.as_ref().ok_or("--e2e-key is required")?.into(),
            authorities: self.e2e_ca.clone(),
            crls: self.e2e_crl.clone(),
            path: self.e2e_path.clone(),
        }
        .load(UnavailablePolicy::Warn)?;
        if let Some(edition) = &self.e2e_edition {
            config.policy.edition = match edition.as_str() {
                "2018" => Edition::First2018,
                "2020" => Edition::Amendment2020,
                _ => return Err("--e2e-edition must be 2018 or 2020".into()),
            };
        }
        if let Some(group) = &self.e2e_group {
            config.policy.dh_groups = vec![match group.as_str() {
                "14" | "modp2048" => Group::Modp2048,
                "23" | "p256" => Group::P256,
                _ => return Err("--e2e-group must be 14 or 23".into()),
            }];
        }
        if let Some(icv) = &self.e2e_icv {
            config.policy.icv_algorithms = vec![match icv.as_str() {
                "hmac-sha256" => IcvAlgorithm::HmacSha256,
                "aes128-gmac" => IcvAlgorithm::GmacAes128,
                "aes256-gmac" => IcvAlgorithm::GmacAes256,
                _ => return Err("unknown --e2e-icv".into()),
            }];
        }
        config.tls_protected = self.enabled();
        #[cfg(feature = "tls")]
        if self.enabled()
            && self
                .options()?
                .certificates
                .iter()
                .any(|c| c.as_ref() == config.identity.certificate)
        {
            return Err("E2E and TLS must use different certificates".into());
        }
        Ok(std::sync::Arc::new(config))
    }

    #[cfg(feature = "tls")]
    fn a_profile(
        &self,
    ) -> Result<std::sync::Arc<iec61850::iec62351::aprofile::Config>, Box<dyn std::error::Error>>
    {
        use iec61850::iec62351::{aprofile, pki::UnavailablePolicy};
        if !self.enabled() && !self.mms_without_tls {
            return Err("A-profile requires TLS or --mms-without-tls".into());
        }
        let mut config = aprofile::Files {
            certificate: self
                .mms_cert
                .as_ref()
                .ok_or("--mms-cert is required")?
                .into(),
            key: self.mms_key.as_ref().ok_or("--mms-key is required")?.into(),
            authorities: self.mms_ca.clone(),
            crls: self.mms_crl.clone(),
            intermediates: Vec::new(),
        }
        .load(UnavailablePolicy::Warn)?;
        config.allow_without_tls = self.mms_without_tls;
        if self.mms_legacy {
            config.mechanism = Some(aprofile::legacy_mechanism());
        }
        Ok(std::sync::Arc::new(config))
    }

    #[cfg(feature = "tls")]
    fn options(&self) -> Result<iec61850::iec62351::Options, Box<dyn std::error::Error>> {
        use rustls::pki_types::{
            pem::PemObject, CertificateDer, CertificateRevocationListDer, PrivateKeyDer,
        };
        let cert = self.cert.as_ref().ok_or("--tls-cert is required")?;
        let key = self.key.as_ref().ok_or("--tls-key is required")?;
        let ca = self.ca.as_ref().ok_or("--tls-ca is required")?;
        let certificates = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
        let roots = CertificateDer::pem_file_iter(ca)?.collect::<Result<Vec<_>, _>>()?;
        let crls = match &self.crl {
            Some(path) => CertificateRevocationListDer::pem_file_iter(path)?
                .map(|v| v.map(|v| v.as_ref().to_vec()))
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        Ok(iec61850::iec62351::Options {
            certificates,
            key: Some(PrivateKeyDer::from_pem_file(key)?),
            roots,
            crls,
            server_name: self.server_name.clone().unwrap_or_default(),
            no_server_name: self.no_server_name,
            tls13_only: self.tls13,
            ..Default::default()
        })
    }

    #[allow(dead_code)]
    pub fn client(
        &self,
        opts: iec61850::client::Options,
    ) -> Result<iec61850::client::Options, Box<dyn std::error::Error>> {
        if !self.enabled() && !self.application_security_enabled() {
            return Ok(opts);
        }
        #[cfg(feature = "tls")]
        {
            let mut opts = opts;
            if self.enabled() {
                opts = opts.with_tls(iec61850::iec62351::client_config(self.options()?)?);
                opts.tls_server_name = self.server_name.clone();
            }
            if self.a_profile_enabled() {
                opts = opts.with_a_profile(self.a_profile()?);
            }
            if self.e2e_enabled() {
                #[cfg(feature = "e2e")]
                {
                    opts = opts.with_e2e(
                        self.e2e()?,
                        self.e2e_peer
                            .as_ref()
                            .ok_or("--e2e-peer is required")?
                            .parse()?,
                    );
                }
                #[cfg(not(feature = "e2e"))]
                return Err("native E2E requires --features e2e".into());
            }
            Ok(opts)
        }
        #[cfg(not(feature = "tls"))]
        Err("TLS requires building with --features tls".into())
    }

    #[allow(dead_code)]
    pub fn server(
        &self,
        opts: iec61850::server::Options,
    ) -> Result<iec61850::server::Options, Box<dyn std::error::Error>> {
        if !self.enabled() && !self.application_security_enabled() {
            return Ok(opts);
        }
        #[cfg(feature = "tls")]
        {
            let mut opts = opts;
            if self.enabled() {
                opts = opts.with_tls(iec61850::iec62351::server_config(self.options()?)?);
            }
            if self.a_profile_enabled() {
                opts = opts.with_a_profile(self.a_profile()?, true);
            }
            if self.e2e_enabled() {
                #[cfg(feature = "e2e")]
                {
                    opts = opts.with_e2e(self.e2e()?, true);
                }
                #[cfg(not(feature = "e2e"))]
                return Err("native E2E requires --features e2e".into());
            }
            Ok(opts)
        }
        #[cfg(not(feature = "tls"))]
        Err("TLS requires building with --features tls".into())
    }
}
