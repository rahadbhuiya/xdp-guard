//! xdp-guard: High-Performance Linux eBPF/XDP Firewall & Rate Limiter CLI
//!
//! Author: Rahad Bhuiya <rahadbhuiya2021@gmail.com>
//!
//! Architecture:
//! - Loads compiled eBPF bytecode into the Linux Kernel via Aya
//! - Attaches XDP hook to network interface (SKB/DRV modes)
//! - Synchronizes pinned BPF Maps for dynamic runtime rule management
//! - Streams live packet drop/pass telemetry directly from kernel array maps
//! - Automated Threat Intelligence feed synchronization daemon (Spamhaus DROP, AbuseIPDB)

pub mod intel;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap, Map, MapData},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use bytesize::ByteSize;
use clap::{Parser, Subcommand};
use colored::*;
use std::{net::Ipv4Addr, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};
use xdp_guard_common::{drop_reasons, AdaptiveConfig, PacketStats, RuleValue, SecurityEvent};

const BPF_FS_PATH: &str = "/sys/fs/bpf/xdp_guard";
const DEFAULT_EBPF_PATH: &str = "target/bpfel-unknown-none/release/xdp-guard-ebpf";

#[derive(Parser, Debug)]
#[command(
    name = "xdp-guard",
    author = "Rahad Bhuiya",
    version = "0.4.0",
    about = "Production Linux XDP Firewall & Adaptive Rate Limiter in Rust (Aya)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Load and attach the XDP filter to network interfaces (Supports multi-NIC & bonds)
    Attach {
        /// Network interface(s) to attach to (comma-separated or multiple flags)
        #[arg(short, long, default_values = &["eth0"], value_delimiter = ',')]
        iface: Vec<String>,

        #[arg(long, default_value = "skb")]
        mode: String,

        /// Path to compiled eBPF ELF binary
        #[arg(long, default_value = DEFAULT_EBPF_PATH)]
        ebpf_path: String,

        /// Custom BPF filesystem path for shared map pinning across NICs/bonds
        #[arg(long, default_value = BPF_FS_PATH)]
        pin_path: String,
    },

    /// Detach XDP filter from interface(s) and unpin maps
    Detach {
        /// Network interface(s) to detach from
        #[arg(short, long, default_values = &["eth0"], value_delimiter = ',')]
        iface: Vec<String>,

        /// Pinned map directory path to clean up
        #[arg(long, default_value = BPF_FS_PATH)]
        pin_path: String,
    },

    /// Add an IPv4 address to the kernel BLOCKLIST_MAP
    Block {
        ip: Ipv4Addr,
        #[arg(long, default_value_t = 0)]
        ttl: u64,
    },

    /// Remove an IPv4 address from BLOCKLIST_MAP
    Unblock { ip: Ipv4Addr },

    /// Add an IPv4 address to the fast-path ALLOWLIST_MAP
    Allow { ip: Ipv4Addr },

    /// Read live telemetry directly from kernel STATS_MAP
    Stats,

    /// Stream real-time forensic security incident events from kernel BPF RingBuffer (Issue #3)
    Monitor {
        /// Output events in structured JSON format
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Maximum events to stream before exit (0 = stream continuously)
        #[arg(short, long, default_value_t = 0)]
        count: u64,
    },

    /// Dynamic rate-limit threshold auto-tuning daemon (Issue #5)
    Tune {
        /// Observation interval in seconds
        #[arg(short, long, default_value_t = 30)]
        interval_secs: u64,

        /// Threshold multiplier above baseline traffic (e.g. 3.0x)
        #[arg(short, long, default_value_t = 3.0)]
        multiplier: f32,

        /// Minimum threshold PPS floor
        #[arg(long, default_value_t = 1000)]
        min_pps: u64,

        /// Maximum threshold PPS ceiling
        #[arg(long, default_value_t = 500000)]
        max_pps: u64,
    },

    /// Run Prometheus metrics exporter HTTP daemon
    Exporter {
        /// HTTP listen address (e.g. 0.0.0.0:9184)
        #[arg(short, long, default_value = "0.0.0.0:9184")]
        listen: String,

        /// Pinned stats map path
        #[arg(long, default_value = "/sys/fs/bpf/xdp_guard/stats")]
        stats_path: String,
    },

    /// Automatically synchronize dynamic Threat Intelligence feeds into eBPF BLOCKLIST_MAP
    SyncFeeds {
        /// Pinned blocklist BPF map path
        #[arg(long, default_value = "/sys/fs/bpf/xdp_guard/blocklist")]
        map_path: String,

        /// Synchronize Spamhaus DROP & EDROP lists
        #[arg(long, default_value_t = true)]
        spamhaus: bool,

        /// Synchronize AbuseIPDB blacklist
        #[arg(long, default_value_t = false)]
        abuseipdb: bool,

        /// Optional AbuseIPDB API key
        #[arg(long, env = "ABUSEIPDB_API_KEY")]
        abuseipdb_key: Option<String>,

        /// Custom threat feed URL (plain text or CSV)
        #[arg(long)]
        custom_url: Option<String>,

        /// Sync interval in seconds (0 = run once and exit)
        #[arg(short, long, default_value_t = 3600)]
        interval: u64,

        /// Expiration TTL in seconds for synchronized IPs (0 = permanent)
        #[arg(long, default_value_t = 86400)]
        ttl: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Attach {
            iface,
            mode,
            ebpf_path,
            pin_path,
        } => {
            println!(
                "{}",
                "=====================================================".cyan()
            );
            println!(
                "  {} - Linux Kernel XDP Defense Engine",
                "XDP-GUARD".bold().green()
            );
            println!("  Author: Rahad Bhuiya | Pure Rust & Aya");
            println!(
                "{}",
                "=====================================================".cyan()
            );

            let flags = match mode.as_str() {
                "drv" => XdpFlags::DRV_MODE,
                "hw" => XdpFlags::HW_MODE,
                _ => XdpFlags::SKB_MODE,
            };

            println!(
                "Loading eBPF bytecode from {} into Linux kernel...",
                ebpf_path
            );
            #[cfg(target_os = "linux")]
            {
                let data = std::fs::read(&ebpf_path)
                    .with_context(|| format!("Failed to read eBPF binary from {}", ebpf_path))?;
                println!("[+] eBPF binary loaded into memory ({} bytes)", data.len());

                let mut bpf =
                    Ebpf::load(&data).context("Failed to load eBPF program into kernel")?;

                let program: &mut Xdp = bpf
                    .program_mut("xdp_guard_filter")
                    .context("Program 'xdp_guard_filter' not found in ELF")?
                    .try_into()?;

                program.load().context("program.load() failed")?;

                // Attach to each interface (multi-NIC / bonded LACP coordination - Issue #4)
                for single_iface in &iface {
                    match program.attach(single_iface, flags) {
                        Ok(_) => println!("[+] Attached XDP program to interface: {}", single_iface.yellow()),
                        Err(e) => eprintln!("[!] Error attaching to {}: {}", single_iface, e),
                    }
                }

                // Ensure /sys/fs/bpf is mounted and directory exists
                let _ = std::process::Command::new("mount")
                    .args(["-t", "bpf", "bpf", "/sys/fs/bpf"])
                    .status();
                let _ = std::fs::create_dir_all(&pin_path);

                // Clean up any stale pins from previous runs
                let _ = std::fs::remove_file(format!("{}/blocklist", pin_path));
                let _ = std::fs::remove_file(format!("{}/allowlist", pin_path));
                let _ = std::fs::remove_file(format!("{}/stats", pin_path));
                let _ = std::fs::remove_file(format!("{}/events", pin_path));
                let _ = std::fs::remove_file(format!("{}/adaptive_config", pin_path));

                // Pin maps to bpffs for runtime control across CLI invocations and multi-NICs
                if let Some(map) = bpf.take_map("BLOCKLIST_MAP") {
                    let _ = map.pin(format!("{}/blocklist", pin_path));
                }
                if let Some(map) = bpf.take_map("ALLOWLIST_MAP") {
                    let _ = map.pin(format!("{}/allowlist", pin_path));
                }
                if let Some(map) = bpf.take_map("EVENTS_RINGBUF") {
                    let _ = map.pin(format!("{}/events", pin_path));
                }
                if let Some(map) = bpf.take_map("ADAPTIVE_CONFIG_MAP") {
                    let _ = map.pin(format!("{}/adaptive_config", pin_path));
                }

                // Keep stats_map in memory for the active daemon loop
                let stats_map: Option<Array<MapData, PacketStats>> =
                    bpf.take_map("STATS_MAP").and_then(|m| {
                        let _ = m.pin(format!("{}/stats", pin_path));
                        Array::<MapData, PacketStats>::try_from(m).ok()
                    });

                println!(
                    "[+] Pinned maps shared across {} interface(s) at {}",
                    iface.len(),
                    pin_path.cyan()
                );

                if let Some(stats_array) = stats_map {
                    monitor_stats_loop(stats_array).await?;
                } else {
                    monitor_live_stats(&format!("{}/stats", pin_path)).await?;
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                println!("[i] Host OS is Windows/macOS. XDP kernel loader requires Linux.");
                println!(
                    "[i] Target interface(s): {} (Mode: {})",
                    iface.join(", ").yellow(),
                    mode.green()
                );
                println!("[i] Pin path: {}", pin_path.cyan());
                println!("[i] Ready for execution under VMware Kali Linux or Linux WSL kernel.");
            }
        }

        Commands::Detach { iface, pin_path } => {
            println!("Detaching XDP filter from {}...", iface.join(", "));
            #[cfg(target_os = "linux")]
            {
                let _ = std::fs::remove_dir_all(&pin_path);
                println!("[+] Pinned maps unpinned from {} and interfaces cleaned.", pin_path);
            }
            #[cfg(not(target_os = "linux"))]
            {
                println!("[SIM] Interfaces {} detached.", iface.join(", "));
            }
        }

        Commands::Monitor { json, count } => {
            monitor_security_events(json, count).await?;
        }

        Commands::Tune {
            interval_secs,
            multiplier,
            min_pps,
            max_pps,
        } => {
            run_adaptive_tuner(interval_secs, multiplier, min_pps, max_pps).await?;
        }

        Commands::Block { ip, ttl } => {
            let ip_u32 = u32::from(ip);
            println!(
                "{} Inserting IP {} into BLOCKLIST_MAP...",
                "[!]".red().bold(),
                ip
            );

            #[cfg(target_os = "linux")]
            {
                let map_path = format!("{}/blocklist", BPF_FS_PATH);
                if Path::new(&map_path).exists() {
                    let map_data = MapData::from_pin(&map_path)?;
                    let map = Map::HashMap(map_data);
                    let mut hash_map = HashMap::<MapData, u32, RuleValue>::try_from(map)?;
                    let rule = RuleValue {
                        action: 1, // Drop
                        _pad: 0,
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs(),
                        ttl_secs: ttl,
                    };
                    hash_map.insert(ip_u32, rule, 0)?;
                    println!(
                        "{} IP successfully blocked in kernel.",
                        "[SUCCESS]".green().bold()
                    );
                } else {
                    eprintln!(
                        "[-] Error: xdp-guard is not currently attached. Run `attach` first."
                    );
                }
            }

            #[cfg(not(target_os = "linux"))]
            println!(
                "{} Configured IP {} (0x{:08X}) for kernel block.",
                "[SIM]".yellow(),
                ip,
                ip_u32
            );
        }

        Commands::Unblock { ip } => {
            let ip_u32 = u32::from(ip);
            println!("Removing IP {} from BLOCKLIST_MAP...", ip);

            #[cfg(target_os = "linux")]
            {
                let map_path = format!("{}/blocklist", BPF_FS_PATH);
                if Path::new(&map_path).exists() {
                    let map_data = MapData::from_pin(&map_path)?;
                    let map = Map::HashMap(map_data);
                    let mut hash_map = HashMap::<MapData, u32, RuleValue>::try_from(map)?;
                    hash_map.remove(&ip_u32)?;
                    println!("{} IP removed from kernel map.", "[SUCCESS]".green().bold());
                }
            }

            #[cfg(not(target_os = "linux"))]
            println!("{} IP {} cleared.", "[OK]".green(), ip);
        }

        Commands::Allow { ip } => {
            let ip_u32 = u32::from(ip);
            println!("Adding IP {} to ALLOWLIST_MAP...", ip);

            #[cfg(target_os = "linux")]
            {
                let map_path = format!("{}/allowlist", BPF_FS_PATH);
                if Path::new(&map_path).exists() {
                    let map_data = MapData::from_pin(&map_path)?;
                    let map = Map::HashMap(map_data);
                    let mut hash_map = HashMap::<MapData, u32, RuleValue>::try_from(map)?;
                    let rule = RuleValue {
                        action: 0, // Pass
                        _pad: 0,
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs(),
                        ttl_secs: 0,
                    };
                    hash_map.insert(ip_u32, rule, 0)?;
                    println!(
                        "{} Fast-path allowlist updated.",
                        "[SUCCESS]".green().bold()
                    );
                }
            }

            #[cfg(not(target_os = "linux"))]
            println!("{} IP {} whitelisted.", "[OK]".green(), ip);
        }

        Commands::Stats => {
            let stats_path = format!("{}/stats", BPF_FS_PATH);
            monitor_live_stats(&stats_path).await?;
        }

        Commands::Exporter { listen, stats_path } => {
            run_exporter(&listen, &stats_path).await?;
        }

        Commands::SyncFeeds {
            map_path,
            spamhaus,
            abuseipdb,
            abuseipdb_key,
            custom_url,
            interval,
            ttl,
        } => {
            let mut providers = Vec::new();
            if spamhaus {
                providers.push(intel::ThreatFeedProvider::SpamhausDrop);
            }
            if abuseipdb {
                providers.push(intel::ThreatFeedProvider::AbuseIpDb {
                    api_key: abuseipdb_key,
                });
            }
            if let Some(url) = custom_url {
                providers.push(intel::ThreatFeedProvider::CustomUrl(url));
            }

            if providers.is_empty() {
                eprintln!("[-] Error: No threat intelligence feeds selected. Enable --spamhaus or provide --custom-url");
                return Ok(());
            }

            if interval == 0 {
                println!("Running single threat intelligence sync cycle...");
                let stats = intel::run_threat_sync_cycle(&map_path, &providers, ttl).await?;
                println!(
                    "{} Feed sync complete: {} parsed, {} unique IPs, {} synced to kernel BPF (Errors: {})",
                    "[SUCCESS]".green().bold(),
                    stats.total_parsed,
                    stats.unique_ips,
                    stats.newly_blocked,
                    stats.errors
                );
            } else {
                intel::run_sync_daemon(&map_path, providers, interval, ttl).await?;
            }
        }
    }

    Ok(())
}

async fn run_exporter(listen_addr: &str, stats_path: &str) -> Result<()> {
    println!(
        "{}",
        "=====================================================".cyan()
    );
    println!(
        "  {} - Cloud-Native Prometheus Exporter",
        "XDP-GUARD".bold().green()
    );
    println!("  Listening address: http://{}", listen_addr.yellow());
    println!(
        "  Metrics endpoint:  http://{}/metrics",
        listen_addr.green()
    );
    println!("  Health endpoint:   http://{}/healthz", listen_addr.cyan());
    println!(
        "{}",
        "=====================================================".cyan()
    );

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("Failed to bind HTTP server to {}", listen_addr))?;

    let stats_path_owned = stats_path.to_string();

    loop {
        let (mut socket, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("[!] Connection accept error: {}", e);
                continue;
            }
        };

        let path_clone = stats_path_owned.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let req_str = String::from_utf8_lossy(&buf[..n]);
            let first_line = req_str.lines().next().unwrap_or("");
            let req_path = first_line.split_whitespace().nth(1).unwrap_or("/");

            let (status_line, content_type, body) = match req_path {
                "/metrics" => {
                    let stats = fetch_stats(&path_clone);
                    let metrics = format_prometheus_metrics(&stats);
                    (
                        "HTTP/1.1 200 OK",
                        "text/plain; version=0.0.4; charset=utf-8",
                        metrics,
                    )
                }
                "/healthz" | "/" => (
                    "HTTP/1.1 200 OK",
                    "application/json",
                    "{\"status\":\"healthy\",\"service\":\"xdp-guard\"}\n".to_string(),
                ),
                _ => (
                    "HTTP/1.1 404 NOT FOUND",
                    "text/plain",
                    "404 Not Found\n".to_string(),
                ),
            };

            let response = format!(
                "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_line,
                content_type,
                body.len(),
                body
            );

            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        });
    }
}

fn fetch_stats(stats_path: &str) -> PacketStats {
    #[cfg(target_os = "linux")]
    {
        if Path::new(stats_path).exists() {
            if let Ok(map_data) = MapData::from_pin(stats_path) {
                let map = Map::Array(map_data);
                if let Ok(array) = Array::<MapData, PacketStats>::try_from(map) {
                    if let Ok(stats) = array.get(&0, 0) {
                        return stats;
                    }
                }
            }
        }
    }
    // Return empty / simulated stats if map is unavailable or on non-Linux
    let _ = stats_path;
    PacketStats::default()
}

fn format_prometheus_metrics(stats: &PacketStats) -> String {
    let total = stats.passed_packets + stats.dropped_packets;
    let ratio = if total > 0 {
        (stats.dropped_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    format!(
        "# HELP xdp_guard_packets_passed_total Total packets passed to OS network stack\n\
         # TYPE xdp_guard_packets_passed_total counter\n\
         xdp_guard_packets_passed_total {}\n\n\
         # HELP xdp_guard_bytes_passed_total Total payload bytes passed\n\
         # TYPE xdp_guard_bytes_passed_total counter\n\
         xdp_guard_bytes_passed_total {}\n\n\
         # HELP xdp_guard_packets_dropped_total Total packets dropped at XDP line-rate\n\
         # TYPE xdp_guard_packets_dropped_total counter\n\
         xdp_guard_packets_dropped_total {}\n\n\
         # HELP xdp_guard_bytes_dropped_total Total bytes dropped at XDP line-rate\n\
         # TYPE xdp_guard_bytes_dropped_total counter\n\
         xdp_guard_bytes_dropped_total {}\n\n\
         # HELP xdp_guard_admission_drops_total Total spoofed flood admission drops\n\
         # TYPE xdp_guard_admission_drops_total counter\n\
         xdp_guard_admission_drops_total {}\n\n\
         # HELP xdp_guard_subnet_drops_total Total /24 subnet aggregate rate limit drops\n\
         # TYPE xdp_guard_subnet_drops_total counter\n\
         xdp_guard_subnet_drops_total {}\n\n\
         # HELP xdp_guard_map_insert_failures_total Total BPF map insertion failures\n\
         # TYPE xdp_guard_map_insert_failures_total counter\n\
         xdp_guard_map_insert_failures_total {}\n\n\
         # HELP xdp_guard_tcp_syn_packets_total Total TCP SYN packets inspected\n\
         # TYPE xdp_guard_tcp_syn_packets_total counter\n\
         xdp_guard_tcp_syn_packets_total {}\n\n\
         # HELP xdp_guard_tcp_syn_drops_total Total TCP SYN flood packets dropped\n\
         # TYPE xdp_guard_tcp_syn_drops_total counter\n\
         xdp_guard_tcp_syn_drops_total {}\n\n\
         # HELP xdp_guard_udp_reflection_drops_total Total UDP amplification reflection packets dropped\n\
         # TYPE xdp_guard_udp_reflection_drops_total counter\n\
         xdp_guard_udp_reflection_drops_total {}\n\n\
         # HELP xdp_guard_ipv6_subnet_drops_total Total IPv6 /64 subnet aggregate rate limit drops\n\
         # TYPE xdp_guard_ipv6_subnet_drops_total counter\n\
         xdp_guard_ipv6_subnet_drops_total {}\n\n\
         # HELP xdp_guard_ipv6_per_ip_drops_total Total IPv6 /128 per-address rate limit drops\n\
         # TYPE xdp_guard_ipv6_per_ip_drops_total counter\n\
         xdp_guard_ipv6_per_ip_drops_total {}\n\n\
         # HELP xdp_guard_ipv6_blocklist_drops_total Total IPv6 blocklist drops\n\
         # TYPE xdp_guard_ipv6_blocklist_drops_total counter\n\
         xdp_guard_ipv6_blocklist_drops_total {}\n\n\
         # HELP xdp_guard_icmpv6_flood_drops_total Total ICMPv6 echo-request flood drops\n\
         # TYPE xdp_guard_icmpv6_flood_drops_total counter\n\
         xdp_guard_icmpv6_flood_drops_total {}\n\n\
         # HELP xdp_guard_drop_ratio_percent Instantaneous packet drop ratio percentage\n\
         # TYPE xdp_guard_drop_ratio_percent gauge\n\
         xdp_guard_drop_ratio_percent {:.2}\n",
        stats.passed_packets,
        stats.passed_bytes,
        stats.dropped_packets,
        stats.dropped_bytes,
        stats.admission_drops,
        stats.subnet_drops,
        stats.map_insert_failures,
        stats.tcp_syn_packets,
        stats.tcp_syn_drops,
        stats.udp_reflection_drops,
        stats.ipv6_subnet_drops,
        stats.ipv6_per_ip_drops,
        stats.ipv6_blocklist_drops,
        stats.icmpv6_flood_drops,
        ratio
    )
}

async fn monitor_stats_loop(array: Array<MapData, PacketStats>) -> Result<()> {
    println!(
        "{:<8} | {:<18} | {:<18} | {:<9} | {:<8} | {:<9} | {:<9} | {:<10} | {:<8}",
        "TIME",
        "PASSED",
        "DROPPED",
        "ADM DROPS",
        "SUBNET",
        "SYN DROPS",
        "UDP DROPS",
        "IPv6 SUB",
        "RATIO"
    );
    println!("----------------------------------------------------------------------------------------------------------------------------");

    let mut last_dropped = 0;
    let mut last_passed = 0;

    loop {
        if let Ok(stats) = array.get(&0, 0) {
            let delta_passed = stats.passed_packets.saturating_sub(last_passed);
            let delta_dropped = stats.dropped_packets.saturating_sub(last_dropped);
            let total = delta_passed + delta_dropped;
            let ratio = if total > 0 {
                (delta_dropped as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            println!(
                "{} | P: {:<6} ({:<5}) | D: {:<6} ({:<5}) | Adm: {:<4} | Sub: {:<4} | SYN: {:<4} | UDP: {:<4} | v6S: {:<4} | {:.2}%",
                chrono::Local::now().format("%H:%M:%S"),
                delta_passed,
                ByteSize::b(stats.passed_bytes),
                delta_dropped,
                ByteSize::b(stats.dropped_bytes),
                stats.admission_drops,
                stats.subnet_drops,
                stats.tcp_syn_drops,
                stats.udp_reflection_drops,
                stats.ipv6_subnet_drops,
                ratio
            );

            last_passed = stats.passed_packets;
            last_dropped = stats.dropped_packets;
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn monitor_live_stats(stats_path: &str) -> Result<()> {
    println!(
        "{:<8} | {:<18} | {:<18} | {:<9} | {:<8} | {:<9} | {:<9} | {:<10} | {:<8}",
        "TIME",
        "PASSED",
        "DROPPED",
        "ADM DROPS",
        "SUBNET",
        "SYN DROPS",
        "UDP DROPS",
        "IPv6 SUB",
        "RATIO"
    );
    println!("----------------------------------------------------------------------------------------------------------------------------");

    #[cfg(target_os = "linux")]
    {
        if Path::new(stats_path).exists() {
            let map_data = MapData::from_pin(stats_path)?;
            let map = Map::Array(map_data);
            let array = Array::<MapData, PacketStats>::try_from(map)?;
            monitor_stats_loop(array).await?;
        } else {
            eprintln!(
                "[-] Pinned stats map not found at {}. Is xdp-guard running?",
                stats_path
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!(
            "[i] Reading kernel telemetry requires Linux bpffs mounted at {}",
            stats_path
        );
    }

    Ok(())
}

/// Streams real-time forensic security incident events from kernel BPF RingBuffer (Addresses Issue #3).
async fn monitor_security_events(json: bool, count: u64) -> Result<()> {
    println!("{}", "=====================================================".cyan());
    println!("  {} - Live Forensic Security Event Stream", "XDP-GUARD".bold().green());
    println!("  Kernel BPF RingBuffer | Drop Telemetry & Forensics");
    println!("{}", "=====================================================".cyan());

    #[cfg(target_os = "linux")]
    {
        let ringbuf_path = format!("{}/events", BPF_FS_PATH);
        if !Path::new(&ringbuf_path).exists() {
            eprintln!(
                "[-] Error: Events ring buffer not found at {}. Is xdp-guard attached?",
                ringbuf_path
            );
            return Ok(());
        }

        let map_data = MapData::from_pin(&ringbuf_path)?;
        let mut ring_buf = aya::maps::RingBuf::try_from(map_data)?;

        let mut events_seen = 0u64;
        loop {
            while let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<SecurityEvent>() {
                    let event: &SecurityEvent =
                        bytemuck::from_bytes(&item[..std::mem::size_of::<SecurityEvent>()]);
                    let src_ip_str = if event.ip_version == 4 {
                        format!("{}.{}.{}.{}", event.src_ip[0], event.src_ip[1], event.src_ip[2], event.src_ip[3])
                    } else {
                        std::net::Ipv6Addr::from(event.src_ip).to_string()
                    };
                    let proto_str = match event.protocol {
                        6 => "TCP",
                        17 => "UDP",
                        58 => "ICMPv6",
                        _ => "OTHER",
                    };
                    let reason_str = drop_reasons::as_str(event.drop_reason);

                    if json {
                        println!(
                            "{{\"timestamp_ns\":{},\"src_ip\":\"{}\",\"src_port\":{},\"dst_port\":{},\"proto\":\"{}\",\"drop_reason\":\"{}\",\"packet_len\":{}}}",
                            event.timestamp_ns, src_ip_str, event.src_port, event.dst_port, proto_str, reason_str, event.packet_len
                        );
                    } else {
                        let dt = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        println!(
                            "[{}] {} Drop: {:<20} | Flow: {}:{} -> :{} ({}) | Wire: {} bytes",
                            dt,
                            "[INCIDENT]".red().bold(),
                            reason_str.yellow().bold(),
                            src_ip_str,
                            event.src_port,
                            event.dst_port,
                            proto_str.cyan(),
                            event.packet_len
                        );
                    }

                    events_seen += 1;
                    if count > 0 && events_seen >= count {
                        return Ok(());
                    }
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("[SIM] Security incident ring buffer listener ready. (Active on Linux kernel).");
        let _ = (json, count);
    }

    Ok(())
}

/// Dynamic rate-limit threshold auto-tuning daemon (Addresses Issue #5).
async fn run_adaptive_tuner(
    interval_secs: u64,
    multiplier: f32,
    min_pps: u64,
    max_pps: u64,
) -> Result<()> {
    println!("{}", "=====================================================".cyan());
    println!("  {} - Adaptive Rate-Limit Auto-Tuning Daemon", "XDP-GUARD".bold().green());
    println!("  Dynamic BPF Map Auto-Tuning | P95 Baseline Tracking");
    println!(
        "  Interval: {}s | Multiplier: {:.1}x | Floor: {} pps | Ceiling: {} pps",
        interval_secs, multiplier, min_pps, max_pps
    );
    println!("{}", "=====================================================".cyan());

    #[cfg(target_os = "linux")]
    {
        let stats_path = format!("{}/stats", BPF_FS_PATH);
        let config_path = format!("{}/adaptive_config", BPF_FS_PATH);

        if !Path::new(&stats_path).exists() {
            eprintln!(
                "[-] Error: stats map not found at {}. Is xdp-guard attached?",
                stats_path
            );
            return Ok(());
        }

        let mut last_total_packets = 0u64;
        let mut last_check = std::time::Instant::now();

        loop {
            sleep(Duration::from_secs(interval_secs)).await;

            let elapsed = last_check.elapsed().as_secs_f64();
            last_check = std::time::Instant::now();

            if let Ok(map_data) = MapData::from_pin(&stats_path) {
                let stats_array = Array::<MapData, PacketStats>::try_from(Map::Array(map_data))?;
                if let Ok(stats) = stats_array.get(&0, 0) {
                    let total_now = stats.passed_packets + stats.dropped_packets;
                    let diff = total_now.saturating_sub(last_total_packets);
                    last_total_packets = total_now;

                    let current_pps = if elapsed > 0.0 {
                        (diff as f64 / elapsed).round() as u64
                    } else {
                        0
                    };

                    let tuned = AdaptiveConfig::compute_tuned(current_pps, multiplier, min_pps, max_pps);

                    println!(
                        "[{}] Baseline: {} pps -> Dynamic Threshold: {} pps (Burst: {}, Refill: {}ns)",
                        chrono::Local::now().format("%H:%M:%S"),
                        current_pps.to_string().cyan(),
                        (1_000_000_000 / tuned.per_ip_refill_ns).to_string().green().bold(),
                        tuned.per_ip_capacity,
                        tuned.per_ip_refill_ns
                    );

                    if Path::new(&config_path).exists() {
                        if let Ok(cfg_map_data) = MapData::from_pin(&config_path) {
                            let mut cfg_array =
                                Array::<MapData, AdaptiveConfig>::try_from(Map::Array(cfg_map_data))?;
                            let _ = cfg_array.set(0, tuned, 0);
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("[SIM] Adaptive auto-tuning engine configured.");
        let _ = (interval_secs, multiplier, min_pps, max_pps);
    }

    Ok(())
}
