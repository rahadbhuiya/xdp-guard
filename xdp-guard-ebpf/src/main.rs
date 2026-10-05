//! xdp-guard-ebpf: High-Performance In-Kernel XDP Filter
//!
//! What is XDP (eXpress Data Path)?
//! Normally, when an Ethernet packet hits a Linux machine, the kernel driver allocates
//! a complex structure called `sk_buff`, pushes it through network namespaces, firewall tables
//! (iptables/nftables), routing tables, and socket buffers. This involves heavy memory allocations
//! and hundreds of CPU cycles per packet.
//!
//! XDP runs *before* any of that! It executes right inside the Network Interface Card (NIC) driver
//! RX queue. If we decide to drop a packet here (`XDP_DROP`), Linux consumes almost ZERO memory
//! and almost ZERO CPU. This is how hyperscalers (Cloudflare, Meta, AWS) survive multi-gigabit DDoS attacks.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap},
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use xdp_guard_common::{PacketStats, RateLimitState, RuleValue};

/// Global or per-rule configuration constants
const RATE_LIMIT_CAPACITY: u64 = 1000; // Maximum burst tokens allowed
const RATE_LIMIT_REFILL_RATE_NS: u64 = 1_000_000; // 1 token every 1ms (1000 packets/sec limit)


// BPF MAPS (Shared state between Kernel and Userspace)


/// Map 0: High-priority Allowlist (IPv4 address -> RuleValue)
/// Packets matching this map bypass all rate-limits and block rules.
#[map]
static ALLOWLIST_MAP: HashMap<u32, RuleValue> = HashMap::<u32, RuleValue>::with_max_entries(65536, 0);

/// Map 1: Fast Blocklist (IPv4 address -> RuleValue)
/// Packets matching this map are instantly dropped at line-rate.
#[map]
static BLOCKLIST_MAP: HashMap<u32, RuleValue> = HashMap::<u32, RuleValue>::with_max_entries(65536, 0);

/// Map 2: Per-IP Token-Bucket Rate Limiter State (LRU Eviction)
/// Tracks packet counts and timestamps using an in-kernel LRU cache.
/// If capacity is exhausted under spoofed floods, the oldest entries
/// are evicted automatically by the kernel without leaking unmetered packets.
#[map]
static RATE_LIMIT_MAP: LruHashMap<u32, RateLimitState> = LruHashMap::<u32, RateLimitState>::with_max_entries(131072, 0);

/// Map 3: Telemetry & Metrics Counters
/// Index 0 stores the global packet statistics (packets passed, bytes passed, dropped, etc.).
#[map]
static STATS_MAP: Array<PacketStats> = Array::<PacketStats>::with_max_entries(1, 0);


// HELPER FUNCTIONS


/// Safely inspects packet memory boundaries.
///
/// The Linux eBPF verifier strictly requires that before reading any byte from a network
/// buffer, we verify `ptr + size <= data_end`. Otherwise, the program is rejected as unsafe.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

/// Increments telemetry metrics in the BPF Array Map.
#[inline(always)]
fn record_metric(passed: bool, packet_bytes: u64) {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe {
            if passed {
                (*stats_ptr).passed_packets += 1;
                (*stats_ptr).passed_bytes += packet_bytes;
            } else {
                (*stats_ptr).dropped_packets += 1;
                (*stats_ptr).dropped_bytes += packet_bytes;
            }
        }
    }
}

/// Increments the map insertion failure counter in the BPF Array Map.
#[inline(always)]
fn record_insert_failure() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).map_insert_failures += 1;
        }
    }
}


// MAIN XDP PROGRAM HOOK


#[xdp]
pub fn xdp_guard_filter(ctx: XdpContext) -> u32 {
    match try_xdp_guard(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // On any parsing failure, safely pass to OS stack
    }
}



/// Core packet inspection and filtering pipeline.
fn try_xdp_guard(ctx: &XdpContext) -> Result<u32, ()> {
    let packet_len = (ctx.data_end() - ctx.data()) as u64;

    // STEP 1: Parse Ethernet Header (Layer 2)
    let eth_hdr_ptr = match ptr_at::<EthHdr>(ctx, 0) {
        Some(ptr) => ptr,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // Notice: EthHdr is a packed struct (repr(C, packed)). Directly referencing its fields
    // is unaligned and causes E0793. We copy the value safely using read_unaligned:
    let ether_type = unsafe { core::ptr::addr_of!((*eth_hdr_ptr).ether_type).read_unaligned() };

    // We only filter IPv4 traffic for this pipeline; pass ARP, IPv6, etc.
    if ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // STEP 2: Parse IPv4 Header (Layer 3)
    let ip_hdr_ptr = match ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN) {
        Some(ptr) => ptr,
        None => return Ok(xdp_action::XDP_PASS),
    };

    let src_addr = unsafe { core::ptr::addr_of!((*ip_hdr_ptr).src_addr).read_unaligned() };
    let src_ip = u32::from_be(src_addr);

    // STEP 3: Check Allowlist (Fast Path)
    // If the source IP is whitelisted (e.g., trusted internal DNS or gateway), allow immediately.
    if unsafe { ALLOWLIST_MAP.get(&src_ip).is_some() } {
        record_metric(true, packet_len);
        return Ok(xdp_action::XDP_PASS);
    }

    // STEP 4: Check Blocklist (Instant Line-rate Drop)
    // If explicitly marked as an attacker, drop before doing any further computation.
    if unsafe { BLOCKLIST_MAP.get(&src_ip).is_some() } {
        record_metric(false, packet_len);
        return Ok(xdp_action::XDP_DROP);
    }

    // STEP 5: In-Kernel Per-IP Token-Bucket Rate Limiter
    // Prevents volumetric floods without blocking legitimate bursty traffic.
    let now_ns = unsafe { bpf_ktime_get_ns() };

    let state = RATE_LIMIT_MAP.get_ptr_mut(&src_ip);

    match state {
        Some(state_ptr) => unsafe {
            let elapsed_ns = now_ns.saturating_sub((*state_ptr).last_update_ns);
            let new_tokens = elapsed_ns / RATE_LIMIT_REFILL_RATE_NS;

            if new_tokens > 0 {
                (*state_ptr).tokens = ((*state_ptr).tokens + new_tokens).min(RATE_LIMIT_CAPACITY);
                (*state_ptr).last_update_ns = now_ns;
            }

            if (*state_ptr).tokens > 0 {
                (*state_ptr).tokens -= 1;
                record_metric(true, packet_len);
                Ok(xdp_action::XDP_PASS)
            } else {
                // Bucket is exhausted: Drop the packet to protect server capacity
                record_metric(false, packet_len);
                Ok(xdp_action::XDP_DROP)
            }
        },
        None => {
            // First time seeing this IP: Initialize the token bucket
            let initial_state = RateLimitState {
                tokens: RATE_LIMIT_CAPACITY.saturating_sub(1),
                last_update_ns: now_ns,
            };
            if RATE_LIMIT_MAP.insert(&src_ip, &initial_state, 0).is_err() {
                record_insert_failure();
                record_metric(false, packet_len);
                Ok(xdp_action::XDP_DROP)
            } else {
                record_metric(true, packet_len);
                Ok(xdp_action::XDP_PASS)
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
