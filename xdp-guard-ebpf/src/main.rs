//! xdp-guard-ebpf: High-Performance In-Kernel XDP Filter with Two-Tier Defense
//!
//! Architecture:
//! - L2 Ethernet parser with IEEE 802.1Q (VLAN) support
//! - Fast-path Allowlist / Blocklist maps
//! - Tier 1: /24 Subnet-level token bucket aggregator (mitigates host-rotating subnet floods)
//! - Tier 2: Per-IP LRU token bucket rate limiter
//! - Ingress Admission Control: Shared admission token bucket for new/unseen flows
//!   (prevents spoofed randomized-IP floods from bypassing rate-limits on map insertion)
//! - Monotonic fractional refill tracking (eliminates sub-millisecond clock drift)

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

/// Per-IP Rate Limiting Configuration
const PER_IP_CAPACITY: u64 = 1000; // Maximum burst tokens per IP
const PER_IP_REFILL_RATE_NS: u64 = 1_000_000; // 1 token every 1ms (1,000 pkts/sec limit)
const INITIAL_BURST_TOKENS: u64 = 10; // Conservative initial allowance on new IP insert

/// Tier 1: /24 Subnet-Level Aggregate Limiting
const SUBNET_CAPACITY: u64 = 5000; // Maximum burst tokens per /24 prefix
const SUBNET_REFILL_RATE_NS: u64 = 200_000; // 1 token every 200us (5,000 pkts/sec per /24)

/// Ingress Admission Control for Unknown Flows
const ADMISSION_CAPACITY: u64 = 2000; // Burst budget for admitting new/unseen sources
const ADMISSION_REFILL_RATE_NS: u64 = 500_000; // 2,000 new source admissions / sec

/// IEEE 802.1Q VLAN EtherTypes
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

// BPF MAPS (Shared state between Kernel and Userspace)

/// Map 0: High-priority Allowlist (IPv4 address -> RuleValue)
#[map]
static ALLOWLIST_MAP: HashMap<u32, RuleValue> = HashMap::<u32, RuleValue>::with_max_entries(65536, 0);

/// Map 1: Fast Blocklist (IPv4 address -> RuleValue)
#[map]
static BLOCKLIST_MAP: HashMap<u32, RuleValue> = HashMap::<u32, RuleValue>::with_max_entries(65536, 0);

/// Map 2: Tier 1 - /24 Subnet Aggregate Rate Limiter (LRU)
/// Keyed on `src_ip & 0xFFFF_FF00`. Bounds total traffic from any /24 prefix.
#[map]
static SUBNET_RATE_LIMIT_MAP: LruHashMap<u32, RateLimitState> = LruHashMap::<u32, RateLimitState>::with_max_entries(32768, 0);

/// Map 3: Tier 2 - Per-IP Token-Bucket Rate Limiter State (LRU Eviction)
#[map]
static RATE_LIMIT_MAP: LruHashMap<u32, RateLimitState> = LruHashMap::<u32, RateLimitState>::with_max_entries(131072, 0);

/// Map 4: Shared Admission Limiter for Unseen Sources
/// Index 0 stores the shared admission token bucket for incoming flows not yet in RATE_LIMIT_MAP.
/// Under randomized-source floods, this admission budget is exhausted immediately, dropping spoofed packets.
#[map]
static ADMISSION_MAP: Array<RateLimitState> = Array::<RateLimitState>::with_max_entries(1, 0);

/// Map 5: Telemetry & Metrics Counters
#[map]
static STATS_MAP: Array<PacketStats> = Array::<PacketStats>::with_max_entries(1, 0);

// HELPER FUNCTIONS

/// Safely inspects packet memory boundaries.
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

/// Token bucket consumption helper with monotonic fractional drift preservation.
#[inline(always)]
fn try_consume_token(
    state: &mut RateLimitState,
    capacity: u64,
    refill_rate_ns: u64,
    now_ns: u64,
) -> bool {
    // If state was newly allocated / uninitialized, initialize with full capacity
    if state.last_update_ns == 0 {
        state.tokens = capacity;
        state.last_update_ns = now_ns;
    }

    let elapsed_ns = now_ns.saturating_sub(state.last_update_ns);
    let new_tokens = elapsed_ns / refill_rate_ns;

    if new_tokens > 0 {
        state.tokens = (state.tokens + new_tokens).min(capacity);
        state.last_update_ns += new_tokens * refill_rate_ns;
    }

    if state.tokens > 0 {
        state.tokens -= 1;
        true
    } else {
        false
    }
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

/// Increments map insertion failure counter.
#[inline(always)]
fn record_insert_failure() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).map_insert_failures += 1;
        }
    }
}

/// Increments admission drop counter under spoofed floods.
#[inline(always)]
fn record_admission_drop() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).admission_drops += 1;
        }
    }
}

/// Increments /24 subnet aggregate drop counter.
#[inline(always)]
fn record_subnet_drop() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).subnet_drops += 1;
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

    let ether_type_raw = unsafe { core::ptr::addr_of!((*eth_hdr_ptr).ether_type).read_unaligned() };
    let mut ether_type_val = u16::from(ether_type_raw);
    let mut l3_offset = EthHdr::LEN;

    // Handle IEEE 802.1Q / 802.1ad (VLAN / QinQ) encapsulation
    if ether_type_val == ETH_P_8021Q || ether_type_val == ETH_P_8021AD {
        let vlan_hdr_ptr = match ptr_at::<u16>(ctx, l3_offset + 2) {
            Some(ptr) => ptr,
            None => return Ok(xdp_action::XDP_PASS),
        };
        let inner_ethertype = unsafe { core::ptr::read_unaligned(vlan_hdr_ptr) };
        ether_type_val = u16::from_be(inner_ethertype);
        l3_offset += 4;
    }

    // Only filter IPv4 traffic; pass non-IPv4 (ARP, IPv6, etc.) to the OS stack
    if ether_type_val != u16::from(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    // STEP 2: Parse IPv4 Header (Layer 3)
    let ip_hdr_ptr = match ptr_at::<Ipv4Hdr>(ctx, l3_offset) {
        Some(ptr) => ptr,
        None => return Ok(xdp_action::XDP_PASS),
    };

    let src_addr = unsafe { core::ptr::addr_of!((*ip_hdr_ptr).src_addr).read_unaligned() };
    let src_ip = u32::from_be(src_addr);

    // STEP 3: Check Allowlist (Fast Path)
    if unsafe { ALLOWLIST_MAP.get(&src_ip).is_some() } {
        record_metric(true, packet_len);
        return Ok(xdp_action::XDP_PASS);
    }

    // STEP 4: Check Blocklist (Instant Line-rate Drop)
    if unsafe { BLOCKLIST_MAP.get(&src_ip).is_some() } {
        record_metric(false, packet_len);
        return Ok(xdp_action::XDP_DROP);
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };

    // STEP 5: Tier 1 - /24 Subnet-Level Aggregate Limiter
    // Prevents host-randomized floods within the same subnet prefix from bypassing limits.
    let subnet_prefix = src_ip & 0xFFFF_FF00;
    let subnet_state = SUBNET_RATE_LIMIT_MAP.get_ptr_mut(&subnet_prefix);

    match subnet_state {
        Some(subnet_ptr) => {
            let allowed = unsafe {
                try_consume_token(&mut *subnet_ptr, SUBNET_CAPACITY, SUBNET_REFILL_RATE_NS, now_ns)
            };
            if !allowed {
                record_subnet_drop();
                record_metric(false, packet_len);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        None => {
            let initial_subnet_state = RateLimitState {
                tokens: SUBNET_CAPACITY.saturating_sub(1),
                last_update_ns: now_ns,
            };
            let _ = SUBNET_RATE_LIMIT_MAP.insert(&subnet_prefix, &initial_subnet_state, 0);
        }
    }

    // STEP 6: Tier 2 - Per-IP Rate Limiter with Ingress Admission Control
    let state = RATE_LIMIT_MAP.get_ptr_mut(&src_ip);

    match state {
        Some(state_ptr) => {
            let allowed = unsafe {
                try_consume_token(&mut *state_ptr, PER_IP_CAPACITY, PER_IP_REFILL_RATE_NS, now_ns)
            };
            if allowed {
                record_metric(true, packet_len);
                Ok(xdp_action::XDP_PASS)
            } else {
                record_metric(false, packet_len);
                Ok(xdp_action::XDP_DROP)
            }
        }
        None => {
            // First time seeing this IP (Unseen Source):
            // Require consuming a token from the shared Admission Budget.
            // Under randomized-IP floods, this budget is exhausted immediately, dropping spoofed packets
            // and protecting the LRU map from churn and legitimate flow eviction.
            let admission_ptr = match ADMISSION_MAP.get_ptr_mut(0) {
                Some(ptr) => ptr,
                None => {
                    record_metric(false, packet_len);
                    return Ok(xdp_action::XDP_DROP);
                }
            };

            let admitted = unsafe {
                try_consume_token(&mut *admission_ptr, ADMISSION_CAPACITY, ADMISSION_REFILL_RATE_NS, now_ns)
            };

            if !admitted {
                record_admission_drop();
                record_metric(false, packet_len);
                return Ok(xdp_action::XDP_DROP);
            }

            // Flow admitted: grant a conservative initial burst (10 tokens, not 1000)
            let initial_state = RateLimitState {
                tokens: INITIAL_BURST_TOKENS.saturating_sub(1),
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
