use crate::config::GeoipConfig;
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Default)]
pub struct GeoipClient {
    reader: Option<Arc<Reader<Vec<u8>>>>,
}

#[derive(Debug, Clone, Default)]
pub struct GeoipResult {
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

impl GeoipClient {
    pub fn new(config: &GeoipConfig) -> Self {
        let reader = config
            .mmdb_path
            .as_ref()
            .and_then(|path| match Reader::open_readfile(path) {
                Ok(r) => {
                    info!(path = %path, "GeoIP MMDB loaded");
                    Some(Arc::new(r))
                }
                Err(e) => {
                    warn!(error = %e, "failed to load GeoIP MMDB; enrichment disabled");
                    None
                }
            });
        GeoipClient { reader }
    }

    pub fn lookup(&self, ip: &IpAddr) -> GeoipResult {
        let Some(ref reader) = self.reader else {
            return GeoipResult::default();
        };

        let city: Option<geoip2::City> = reader
            .lookup(*ip)
            .ok()
            .and_then(|result| result.decode().ok().flatten());
        let country = city
            .as_ref()
            .and_then(|c| c.country.iso_code)
            .map(str::to_string);

        let city_name = city
            .as_ref()
            .and_then(|c| c.city.names.english)
            .map(str::to_string);

        GeoipResult {
            country,
            city: city_name,
            asn: None,
            org: None,
        }
    }

    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }
}
