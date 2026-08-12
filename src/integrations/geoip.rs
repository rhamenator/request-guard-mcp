use crate::config::GeoipConfig;
use anyhow::{Context, Result};
use maxminddb::{geoip2, Reader};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

type MmdbReader = Arc<Reader<Vec<u8>>>;

#[derive(Default)]
pub struct GeoipClient {
    city_reader: Option<MmdbReader>,
    asn_reader: Option<MmdbReader>,
    anonymous_reader: Option<MmdbReader>,
    asn_index: HashMap<u32, String>,
}

#[derive(Debug, Clone, Default)]
pub struct GeoipResult {
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub is_proxy: bool,
    pub is_datacenter: bool,
    pub is_tor: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AsnResult {
    pub organization: Option<String>,
    pub is_hosting: bool,
}

impl GeoipClient {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn load(config: &GeoipConfig) -> Result<Self> {
        let city_path = config.city_mmdb_path.as_ref().or(config.mmdb_path.as_ref());
        let city_reader = open_optional(city_path, "City")?;
        let asn_reader = open_optional(config.asn_mmdb_path.as_ref(), "ASN")?;
        let anonymous_reader =
            open_optional(config.anonymous_ip_mmdb_path.as_ref(), "Anonymous IP")?;
        let asn_index = asn_reader
            .as_ref()
            .map(build_asn_index)
            .transpose()?
            .unwrap_or_default();
        if city_reader.is_some() || asn_reader.is_some() || anonymous_reader.is_some() {
            info!(
                city = city_reader.is_some(),
                asn = asn_reader.is_some(),
                anonymous_ip = anonymous_reader.is_some(),
                indexed_asns = asn_index.len(),
                "MaxMind enrichment initialized"
            );
        }
        Ok(Self {
            city_reader,
            asn_reader,
            anonymous_reader,
            asn_index,
        })
    }

    pub fn lookup_ip(&self, ip: &IpAddr) -> Result<GeoipResult> {
        let mut result = GeoipResult::default();
        if let Some(reader) = &self.city_reader {
            if let Some(city) = reader
                .lookup(*ip)
                .context("GeoIP City lookup failed")?
                .decode::<geoip2::City>()
                .context("GeoIP City record decode failed")?
            {
                result.country = city.country.iso_code.map(str::to_string);
                result.city = city.city.names.english.map(str::to_string);
            }
        }
        if let Some(reader) = &self.asn_reader {
            if let Some(asn) = reader
                .lookup(*ip)
                .context("GeoIP ASN lookup failed")?
                .decode::<geoip2::Asn>()
                .context("GeoIP ASN record decode failed")?
            {
                result.asn = asn.autonomous_system_number;
                result.org = asn.autonomous_system_organization.map(str::to_string);
                result.is_datacenter = result.org.as_deref().is_some_and(is_hosting_org);
            }
        }
        if let Some(reader) = &self.anonymous_reader {
            if let Some(anonymous) = reader
                .lookup(*ip)
                .context("GeoIP Anonymous IP lookup failed")?
                .decode::<geoip2::AnonymousIp>()
                .context("GeoIP Anonymous IP record decode failed")?
            {
                result.is_proxy = anonymous.is_anonymous.unwrap_or(false)
                    || anonymous.is_anonymous_vpn.unwrap_or(false)
                    || anonymous.is_public_proxy.unwrap_or(false)
                    || anonymous.is_residential_proxy.unwrap_or(false);
                result.is_datacenter |= anonymous.is_hosting_provider.unwrap_or(false);
                result.is_tor = anonymous.is_tor_exit_node.unwrap_or(false);
            }
        }
        Ok(result)
    }

    pub fn lookup_asn(&self, asn: u32) -> Option<AsnResult> {
        self.asn_index.get(&asn).map(|organization| AsnResult {
            organization: Some(organization.clone()),
            is_hosting: is_hosting_org(organization),
        })
    }

    pub fn is_available(&self) -> bool {
        self.city_reader.is_some() || self.asn_reader.is_some() || self.anonymous_reader.is_some()
    }

    pub fn has_ip_database(&self) -> bool {
        self.is_available()
    }

    pub fn has_asn_database(&self) -> bool {
        self.asn_reader.is_some()
    }
}

fn open_optional(path: Option<&String>, database_name: &str) -> Result<Option<MmdbReader>> {
    path.map(|path| {
        Reader::open_readfile(path)
            .context(format!(
                "failed to load configured {} MMDB at {}",
                database_name, path
            ))
            .map(Arc::new)
    })
    .transpose()
}

fn build_asn_index(reader: &MmdbReader) -> Result<HashMap<u32, String>> {
    let mut index = HashMap::new();
    for lookup in reader
        .networks(Default::default())
        .context("failed to iterate ASN MMDB")?
    {
        let lookup = lookup.context("failed to read ASN MMDB network")?;
        if let Some(record) = lookup
            .decode::<geoip2::Asn>()
            .context("failed to decode ASN MMDB record")?
        {
            if let (Some(asn), Some(organization)) = (
                record.autonomous_system_number,
                record.autonomous_system_organization,
            ) {
                index.entry(asn).or_insert_with(|| organization.to_string());
            }
        }
    }
    Ok(index)
}

pub fn is_hosting_org(organization: &str) -> bool {
    let organization = organization.to_ascii_lowercase();
    [
        "hosting",
        "cloud",
        "data center",
        "datacenter",
        "digitalocean",
        "amazon",
        "google",
        "microsoft",
        "ovh",
        "hetzner",
        "linode",
        "vultr",
    ]
    .iter()
    .any(|marker| organization.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_hosting_organizations() {
        assert!(is_hosting_org("Amazon.com, Inc."));
        assert!(is_hosting_org("Example Cloud Hosting Ltd"));
        assert!(!is_hosting_org("Example Residential Broadband"));
    }

    #[test]
    fn missing_database_configuration_is_supported() {
        let client = GeoipClient::load(&GeoipConfig::default()).unwrap();
        assert!(!client.is_available());
    }
}
