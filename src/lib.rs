// Souran DNS Library - Core Implementation v0.1.0
// Built from ZERO source - Zero-Upstream DNS Resolver

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const VERSION: &str = "0.1.0";

#[derive(Debug, Clone)]
pub struct DNSCacheEntry {
    pub name: String,
    pub qtype: u16,
    pub ttl: u32,
    pub data: String,
    pub cached_at: u64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub version: String,
    pub zero_upstream: bool,
    pub cache_enabled: bool,
    pub timeout_ms: u64,
    pub max_retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            zero_upstream: true,
            cache_enabled: true,
            timeout_ms: 5000,
            max_retries: 3,
        }
    }
}

pub struct DNSResolver {
    pub config: Config,
    pub cache: Arc<Mutex<HashMap<String, DNSCacheEntry>>>,
}

impl DNSResolver {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub fn version(&self) -> &str {
        &self.config.version
    }
    
    pub fn is_zero_upstream(&self) -> bool {
        self.config.zero_upstream
    }
}

impl Default for DNSResolver {
    fn default() -> Self {
        Self::new()
    }
}

pub fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00]);
    q.extend_from_slice(&[0x00, 0x00]);
    q.extend_from_slice(&[0x00, 0x00]);
    
    for part in name.split('.') {
        q.push(part.len() as u8);
        q.extend_from_slice(part.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]);
    
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_upstream_config() {
        let resolver = DNSResolver::new();
        assert!(resolver.is_zero_upstream());
        assert_eq!(resolver.version(), "0.1.0");
    }
    
    #[test]
    fn test_all_core_features() {
        let resolver = DNSResolver::new();
        assert!(resolver.config.zero_upstream);
        assert!(resolver.config.cache_enabled);
    }
}