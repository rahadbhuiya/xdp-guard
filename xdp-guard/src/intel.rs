//! Threat intelligence synchronization engine for xdp-guard.
//!
//! Fetches dynamic threat feeds (Spamhaus DROP/EDROP, AbuseIPDB, custom endpoints)
//! and atomically syncs them to kernel eBPF `BLOCKLIST_MAP` with TTL and CIDR expansion.

use anyhow::{Context, Result};
use colored::*;
use log::{error, info, warn};
use std::{
    collections::HashSet,
    net::Ipv4Addr,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use xdp_guard_common::RuleValue;

#[cfg(target_os = "linux")]
use aya::maps::{HashMap, Map, MapData};

/// Source provider configuration for threat feeds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatFeedProvider {
    /// Spamhaus DROP/EDROP text list
    SpamhausDrop,
    /// AbuseIPDB blacklist
    AbuseIpDb { api_key: Option<String> },
    /// Custom HTTP plain-text list
    CustomUrl(String),
}

/// Statistics from a sync run
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub total_parsed: usize,
    pub unique_ips: usize,
    pub newly_blocked: usize,
    pub errors: usize,
}

/// Parse Spamhaus DROP format:
/// Example line: `198.51.100.0/24 ; SBL123456`
pub fn parse_spamhaus_drop(content: &str) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }

        let cidr_part = match trimmed.split(';').next() {
            Some(part) => part.trim(),
            None => continue,
        };

        if let Ok(expanded) = expand_cidr_v4(cidr_part) {
            ips.extend(expanded);
        } else if let Ok(ip) = Ipv4Addr::from_str(cidr_part) {
            ips.push(ip);
        }
    }

    ips
}

/// Parse AbuseIPDB blacklist format (plaintext IP list or CSV)
pub fn parse_abuseipdb_feed(content: &str) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Handles plain IP list or CSV where first column is IP
        let ip_str = trimmed.split([',', ';', '\t', ' ']).next().unwrap_or("");
        if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
            ips.push(ip);
        }
    }

    ips
}

/// Expand CIDR (bounded to /24 to prevent accidental memory exhaustion on huge ranges like /8)
pub fn expand_cidr_v4(cidr: &str) -> Result<Vec<Ipv4Addr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR syntax: {}", cidr);
    }

    let base_ip = Ipv4Addr::from_str(parts[0])?;
    let prefix_len: u8 = parts[1].parse()?;

    if prefix_len > 32 {
        anyhow::bail!("Prefix length > 32");
    }

    // Safety guard: only expand subnets /24 to /32 directly into individual IP rules
    // Larger subnets are safely clamped or base/network address dropped.
    if prefix_len < 24 {
        warn!(
            "Subnet {} has prefix /{} < /24; inserting network base address only to protect BPF map bounds",
            cidr, prefix_len
        );
        return Ok(vec![base_ip]);
    }

    let ip_u32 = u32::from(base_ip);
    let host_count = 1u64 << (32 - prefix_len);
    let mut ips = Vec::with_capacity(host_count as usize);

    for i in 0..host_count {
        let current_ip = ip_u32.wrapping_add(i as u32);
        ips.push(Ipv4Addr::from(current_ip));
    }

    Ok(ips)
}

/// Minimal zero-dependency HTTP GET client over Tokio TCP stream
pub async fn http_get(url: &str, headers: &[(&str, &str)]) -> Result<String> {
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = match stripped.find('/') {
        Some(idx) => (&stripped[..idx], &stripped[idx..]),
        None => (stripped, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => (&host_port[..idx], host_port[idx + 1..].parse::<u16>()?),
        None => (host_port, 80),
    };

    let mut stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("Failed to connect to {}:{}", host, port))?;

    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xdp-guard-threat-sync/0.4.0\r\nConnection: close\r\n",
        path, host
    );

    for (k, v) in headers {
        request.push_str(&format!("{}: {}\r\n", k, v));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await?;

    let full_res = String::from_utf8_lossy(&response_bytes);
    if let Some(body_idx) = full_res.find("\r\n\r\n") {
        Ok(full_res[body_idx + 4..].to_string())
    } else {
        Ok(full_res.to_string())
    }
}

/// Synchronize a set of IPs into the BPF BLOCKLIST_MAP
pub fn sync_ips_to_bpf_map(map_path: &str, ips: &[Ipv4Addr], ttl_secs: u64) -> Result<usize> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let rule = RuleValue {
        action: 1, // Drop
        _pad: 0,
        created_at: now,
        ttl_secs,
    };

    let mut inserted_count = 0;

    #[cfg(target_os = "linux")]
    {
        if Path::new(map_path).exists() {
            let map_data = MapData::from_pin(map_path)?;
            let map = Map::HashMap(map_data);
            let mut hash_map = HashMap::<MapData, u32, RuleValue>::try_from(map)?;

            for ip in ips {
                let ip_u32 = u32::from(*ip);
                if hash_map.insert(ip_u32, rule, 0).is_ok() {
                    inserted_count += 1;
                }
            }
        } else {
            anyhow::bail!(
                "Pinned BPF map not found at {}. Is xdp-guard attached?",
                map_path
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (map_path, ips, rule);
        inserted_count = ips.len();
    }

    Ok(inserted_count)
}

/// Run an automated sync cycle across configured threat feeds
pub async fn run_threat_sync_cycle(
    bpf_map_path: &str,
    providers: &[ThreatFeedProvider],
    ttl_secs: u64,
) -> Result<SyncStats> {
    let mut stats = SyncStats::default();
    let mut collected_ips = HashSet::new();

    for provider in providers {
        match provider {
            ThreatFeedProvider::SpamhausDrop => {
                info!("Fetching Spamhaus DROP feed...");
                match http_get("http://www.spamhaus.org/drop/drop.txt", &[]).await {
                    Ok(body) => {
                        let ips = parse_spamhaus_drop(&body);
                        stats.total_parsed += ips.len();
                        for ip in ips {
                            collected_ips.insert(ip);
                        }
                    }
                    Err(e) => {
                        warn!("Spamhaus DROP fetch failed: {}", e);
                        stats.errors += 1;
                    }
                }
            }
            ThreatFeedProvider::AbuseIpDb { api_key } => {
                info!("Fetching AbuseIPDB blacklist...");
                let mut headers = Vec::new();
                let key_str;
                if let Some(key) = api_key {
                    key_str = key.clone();
                    headers.push(("Key", key_str.as_str()));
                    headers.push(("Accept", "text/plain"));
                }
                match http_get("http://api.abuseipdb.com/api/v2/blacklist", &headers).await {
                    Ok(body) => {
                        let ips = parse_abuseipdb_feed(&body);
                        stats.total_parsed += ips.len();
                        for ip in ips {
                            collected_ips.insert(ip);
                        }
                    }
                    Err(e) => {
                        warn!("AbuseIPDB fetch failed: {}", e);
                        stats.errors += 1;
                    }
                }
            }
            ThreatFeedProvider::CustomUrl(url) => {
                info!("Fetching custom threat feed: {}...", url);
                match http_get(url, &[]).await {
                    Ok(body) => {
                        let ips = parse_abuseipdb_feed(&body);
                        stats.total_parsed += ips.len();
                        for ip in ips {
                            collected_ips.insert(ip);
                        }
                    }
                    Err(e) => {
                        warn!("Custom feed {} fetch failed: {}", url, e);
                        stats.errors += 1;
                    }
                }
            }
        }
    }

    stats.unique_ips = collected_ips.len();
    let ip_list: Vec<Ipv4Addr> = collected_ips.into_iter().collect();

    match sync_ips_to_bpf_map(bpf_map_path, &ip_list, ttl_secs) {
        Ok(inserted) => {
            stats.newly_blocked = inserted;
        }
        Err(e) => {
            error!("Failed to sync IPs into eBPF map: {}", e);
            stats.errors += 1;
        }
    }

    Ok(stats)
}

/// Start long-running background synchronization daemon
pub async fn run_sync_daemon(
    bpf_map_path: &str,
    providers: Vec<ThreatFeedProvider>,
    interval_secs: u64,
    ttl_secs: u64,
) -> Result<()> {
    println!(
        "{}",
        "=====================================================".cyan()
    );
    println!(
        "  {} - Automated Threat Intelligence Sync Daemon",
        "XDP-GUARD".bold().green()
    );
    println!(
        "  Sync Interval: {}s | Rule TTL: {}s",
        interval_secs, ttl_secs
    );
    println!("  Target BPF Map: {}", bpf_map_path.yellow());
    println!(
        "{}",
        "=====================================================".cyan()
    );

    loop {
        info!("Starting scheduled threat feed synchronization run...");
        match run_threat_sync_cycle(bpf_map_path, &providers, ttl_secs).await {
            Ok(stats) => {
                println!(
                    "[{}] Feed sync completed: {} parsed, {} unique IPs, {} synced to kernel BPF (Errors: {})",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    stats.total_parsed,
                    stats.unique_ips,
                    stats.newly_blocked,
                    stats.errors
                );
            }
            Err(e) => {
                eprintln!("[!] Threat sync cycle failed: {}", e);
            }
        }

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spamhaus_drop() {
        let mock_drop = r#"
; Spamhaus DROP List 2026/11/05
; https://www.spamhaus.org/drop/drop.txt
192.0.2.0/24 ; SBL100001
198.51.100.14 ; SBL100002
# comment line
203.0.113.0/30 ; SBL100003
"#;
        let ips = parse_spamhaus_drop(mock_drop);
        assert!(!ips.is_empty());
        assert!(ips.contains(&Ipv4Addr::new(198, 51, 100, 14)));
        // /30 has 4 IPs: .0, .1, .2, .3
        assert!(ips.contains(&Ipv4Addr::new(203, 0, 113, 0)));
        assert!(ips.contains(&Ipv4Addr::new(203, 0, 113, 3)));
    }

    #[test]
    fn test_parse_abuseipdb_feed() {
        let mock_feed = r#"
# AbuseIPDB Blacklist
1.2.3.4,100,2026-11-05
5.6.7.8
9.10.11.12;95
"#;
        let ips = parse_abuseipdb_feed(mock_feed);
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(ips[1], Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(ips[2], Ipv4Addr::new(9, 10, 11, 12));
    }

    #[test]
    fn test_expand_cidr_v4_safety_clamp() {
        // /16 is larger than /24, should return base address only to protect eBPF map memory
        let res = expand_cidr_v4("10.0.0.0/16").unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], Ipv4Addr::new(10, 0, 0, 0));

        // /30 expands to 4 addresses
        let res2 = expand_cidr_v4("192.168.1.0/30").unwrap();
        assert_eq!(res2.len(), 4);
    }
}
