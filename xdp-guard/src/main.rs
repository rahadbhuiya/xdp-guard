//! xdp-guard: High-Performance Linux eBPF/XDP Firewall & Rate Limiter CLI
//!
//! Author: Rahad Bhuiya <rahadbhuiya2021@gmail.com>
//!
//! Architecture:
//! - Loads compiled eBPF bytecode into the Linux Kernel via Aya
//! - Attaches XDP hook to network interface (SKB/DRV modes)
//! - Synchronizes pinned BPF Maps for dynamic runtime rule management
//! - Streams live packet drop/pass telemetry directly from kernel array maps

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
use tokio::time::sleep;
use xdp_guard_common::{PacketStats, RuleValue};

const BPF_FS_PATH: &str = "/sys/fs/bpf/xdp_guard";
const DEFAULT_EBPF_PATH: &str = "target/bpfel-unknown-none/release/xdp-guard-ebpf";

#[derive(Parser, Debug)]
#[command(
    name = "xdp-guard",
    author = "Rahad Bhuiya",
    version = "0.1.0",
    about = "Production Linux XDP Firewall & Per-IP Rate Limiter in Rust (Aya)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Load and attach the XDP filter to a network interface
    Attach {
        #[arg(short, long, default_value = "eth0")]
        iface: String,

        #[arg(long, default_value = "skb")]
        mode: String,

        /// Path to compiled eBPF ELF binary
        #[arg(long, default_value = DEFAULT_EBPF_PATH)]
        ebpf_path: String,
    },

    /// Detach XDP filter from interface and unpin maps
    Detach {
        #[arg(short, long, default_value = "eth0")]
        iface: String,
    },

    /// Add an IPv4 address to the kernel BLOCKLIST_MAP
    Block {
        ip: Ipv4Addr,
        #[arg(long, default_value_t = 0)]
        ttl: u64,
    },

    /// Remove an IPv4 address from BLOCKLIST_MAP
    Unblock {
        ip: Ipv4Addr,
    },

    /// Add an IPv4 address to the fast-path ALLOWLIST_MAP
    Allow {
        ip: Ipv4Addr,
    },

    /// Read live telemetry directly from kernel STATS_MAP
    Stats,
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
        } => {
            println!("{}", "=====================================================".cyan());
            println!("  {} - Linux Kernel XDP Defense Engine", "XDP-GUARD".bold().green());
            println!("  Author: Rahad Bhuiya | Pure Rust & Aya");
            println!("{}", "=====================================================".cyan());

            let flags = match mode.as_str() {
                "drv" => XdpFlags::DRV_MODE,
                "hw" => XdpFlags::HW_MODE,
                _ => XdpFlags::SKB_MODE,
            };

            println!("Loading eBPF bytecode from {} into Linux kernel...", ebpf_path);
            #[cfg(target_os = "linux")]
            {
                let data = std::fs::read(&ebpf_path)
                    .with_context(|| format!("Failed to read eBPF binary from {}", ebpf_path))?;
                println!("[+] eBPF binary loaded into memory ({} bytes)", data.len());

                let mut bpf = Ebpf::load(&data).context("Failed to load eBPF program into kernel")?;

                let program: &mut Xdp = bpf
                    .program_mut("xdp_guard_filter")
                    .context("Program 'xdp_guard_filter' not found in ELF")?
                    .try_into()?;

                program.load().context("program.load() failed")?;
                program.attach(&iface, flags).context("program.attach() failed")?;


                // Ensure /sys/fs/bpf is mounted and directory exists
                let _ = std::process::Command::new("mount")
                    .args(["-t", "bpf", "bpf", "/sys/fs/bpf"])
                    .status();
                let _ = std::fs::create_dir_all(BPF_FS_PATH);

                // Clean up any stale pins from previous runs
                let _ = std::fs::remove_file(format!("{}/blocklist", BPF_FS_PATH));
                let _ = std::fs::remove_file(format!("{}/allowlist", BPF_FS_PATH));
                let _ = std::fs::remove_file(format!("{}/stats", BPF_FS_PATH));

                // Pin maps to bpffs for runtime control across CLI invocations
                if let Some(map) = bpf.take_map("BLOCKLIST_MAP") {
                    match map.pin(format!("{}/blocklist", BPF_FS_PATH)) {
                        Ok(_) => println!("[+] Successfully pinned BLOCKLIST_MAP to {}/blocklist", BPF_FS_PATH),
                        Err(e) => eprintln!("[!] Error pinning blocklist: {}", e),
                    }
                } else {
                    eprintln!("[!] Warning: BLOCKLIST_MAP not found in bpf.take_map()");
                }

                if let Some(map) = bpf.take_map("ALLOWLIST_MAP") {
                    match map.pin(format!("{}/allowlist", BPF_FS_PATH)) {
                        Ok(_) => println!("[+] Successfully pinned ALLOWLIST_MAP to {}/allowlist", BPF_FS_PATH),
                        Err(e) => eprintln!("[!] Error pinning allowlist: {}", e),
                    }
                } else {
                    eprintln!("[!] Warning: ALLOWLIST_MAP not found in bpf.take_map()");
                }

                // Keep stats_map in memory for the active daemon loop
                let stats_map: Option<Array<MapData, PacketStats>> = bpf
                    .take_map("STATS_MAP")
                    .and_then(|m| {
                        let _ = m.pin(format!("{}/stats", BPF_FS_PATH));
                        Array::<MapData, PacketStats>::try_from(m).ok()
                    });

                println!("[+] Attached to interface: {} (Mode: {})", iface.yellow(), mode.green());

                if let Some(stats_array) = stats_map {
                    monitor_stats_loop(stats_array).await?;
                } else {
                    monitor_live_stats(&format!("{}/stats", BPF_FS_PATH)).await?;
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                println!("[i] Host OS is Windows/macOS. XDP kernel loader requires Linux.");
                println!("[i] Target interface: {} (Mode: {})", iface.yellow(), mode.green());
                println!("[i] Ready for execution under VMware Kali Linux or Linux WSL kernel.");
            }
        }

        Commands::Detach { iface } => {
            println!("Detaching XDP filter from {}...", iface);
            #[cfg(target_os = "linux")]
            {
                let _ = std::fs::remove_dir_all(BPF_FS_PATH);
                println!("[+] Maps unpinned and interface cleaned.");
            }
        }

        Commands::Block { ip, ttl } => {
            let ip_u32 = u32::from(ip);
            println!("{} Inserting IP {} into BLOCKLIST_MAP...", "[!]".red().bold(), ip);

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
                    println!("{} IP successfully blocked in kernel.", "[SUCCESS]".green().bold());
                } else {
                    eprintln!("[-] Error: xdp-guard is not currently attached. Run `attach` first.");
                }
            }

            #[cfg(not(target_os = "linux"))]
            println!("{} Configured IP {} (0x{:08X}) for kernel block.", "[SIM]".yellow(), ip, ip_u32);
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
                    println!("{} Fast-path allowlist updated.", "[SUCCESS]".green().bold());
                }
            }

            #[cfg(not(target_os = "linux"))]
            println!("{} IP {} whitelisted.", "[OK]".green(), ip);
        }

        Commands::Stats => {
            let stats_path = format!("{}/stats", BPF_FS_PATH);
            monitor_live_stats(&stats_path).await?;
        }
    }

    Ok(())
}

async fn monitor_stats_loop(array: Array<MapData, PacketStats>) -> Result<()> {
    println!("{:<10} | {:<20} | {:<20} | {:<16} | {:<14} | {:<10}", "TIME", "PASSED", "DROPPED", "ADM DROPS", "SUBNET DROPS", "DROP RATIO");
    println!("--------------------------------------------------------------------------------------------------------------------");

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
                "{} | Pass: {:<7} ({:<6}) | Drop: {:<7} ({:<6}) | Adm: {:<10} | Subnet: {:<8} | Ratio: {:.2}%",
                chrono::Local::now().format("%H:%M:%S"),
                delta_passed,
                ByteSize::b(stats.passed_bytes),
                delta_dropped,
                ByteSize::b(stats.dropped_bytes),
                stats.admission_drops,
                stats.subnet_drops,
                ratio
            );

            last_passed = stats.passed_packets;
            last_dropped = stats.dropped_packets;
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn monitor_live_stats(stats_path: &str) -> Result<()> {
    println!("{:<10} | {:<20} | {:<20} | {:<16} | {:<14} | {:<10}", "TIME", "PASSED", "DROPPED", "ADM DROPS", "SUBNET DROPS", "DROP RATIO");
    println!("--------------------------------------------------------------------------------------------------------------------");

    #[cfg(target_os = "linux")]
    {
        if Path::new(stats_path).exists() {
            let map_data = MapData::from_pin(stats_path)?;
            let map = Map::Array(map_data);
            let array = Array::<MapData, PacketStats>::try_from(map)?;
            monitor_stats_loop(array).await?;
        } else {
            eprintln!("[-] Pinned stats map not found at {}. Is xdp-guard running?", stats_path);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("[i] Reading kernel telemetry requires Linux bpffs mounted at {}", stats_path);
    }

    Ok(())
}
