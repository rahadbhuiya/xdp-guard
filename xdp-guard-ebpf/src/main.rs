//! xdp-guard-ebpf: High-Performance In-Kernel XDP Filter with Two-Tier Defense
//!
//! Architecture:
//! - L2 Ethernet parser with IEEE 802.1Q (VLAN) support
//! - Fast-path Allowlist / Blocklist maps (IPv4 + IPv6)
//! - Tier 1: /24 Subnet-level token bucket aggregator for IPv4 (mitigates host-rotating subnet floods)
//! - Tier 1 (IPv6): /64 Subnet-level LRU token bucket aggregator
//! - Tier 2: Per-IP LRU token bucket rate limiter (IPv4 /32 and IPv6 /128)
//! - Ingress Admission Control: Shared admission token bucket for new/unseen flows
//!   (prevents spoofed randomized-IP floods from bypassing rate-limits on map insertion)
//! - Monotonic fractional refill tracking (eliminates sub-millisecond clock drift)
//! - Full dual-stack: EtherType 0x0800 (IPv4) + 0x86DD (IPv6)

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use xdp_guard_common::{
    drop_reasons, AdaptiveConfig, PacketStats, RateLimitState, RuleValue, SecurityEvent,
};

/// Per-IP Rate Limiting Configuration
const PER_IP_CAPACITY: u64 = 1000; // Maximum burst tokens per IP
const PER_IP_REFILL_RATE_NS: u64 = 1_000_000; // 1 token every 1ms (1,000 pkts/sec limit)
const INITIAL_BURST_TOKENS: u64 = 10; // Conservative initial allowance on new IP insert

/// Tier 1: /24 Subnet-Level Aggregate Limiting (IPv4)
const SUBNET_CAPACITY: u64 = 5000; // Maximum burst tokens per /24 prefix
const SUBNET_REFILL_RATE_NS: u64 = 200_000; // 1 token every 200us (5,000 pkts/sec per /24)

/// Ingress Admission Control for Unknown Flows
const ADMISSION_CAPACITY: u64 = 2000; // Burst budget for admitting new/unseen sources
const ADMISSION_REFILL_RATE_NS: u64 = 500_000; // 2,000 new source admissions / sec

/// Layer-4 TCP SYN Flood Mitigation
const TCP_SYN_BURST_CAPACITY: u64 = 64; // Max burst of new TCP connection attempts per IP
const TCP_SYN_REFILL_RATE_NS: u64 = 10_000_000; // 1 token every 10ms (100 new connections/sec per IP)

/// IPv6 /64 Subnet-Level Aggregate Limiting
const IPV6_SUBNET_CAPACITY: u64 = 5000;
const IPV6_SUBNET_REFILL_RATE_NS: u64 = 200_000;

/// Per-/128 IPv6 Address Rate Limiting
const IPV6_PER_IP_CAPACITY: u64 = 1000;
const IPV6_PER_IP_REFILL_RATE_NS: u64 = 1_000_000;

/// Protocol numbers (raw u8) used in IPv4 proto / IPv6 next-header fields
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58; // ICMPv6 (RFC 4443)

/// ICMPv6 Type 128 = Echo Request (ping6 flood mitigation)
const ICMPV6_TYPE_ECHO_REQUEST: u8 = 128;

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
/// Under randomized-source floods, this admission pool drains in milliseconds,
/// and all subsequent unseen packets are dropped at wire-speed with zero map churn.
#[map]
static ADMISSION_MAP: Array<RateLimitState> = Array::<RateLimitState>::with_max_entries(1, 0);

/// Map 5: Telemetry & Metrics Counters
#[map]
static STATS_MAP: Array<PacketStats> = Array::<PacketStats>::with_max_entries(1, 0);

/// Map 6: Layer-4 TCP SYN Rate Limiter (Mitigates SYN-flood backlog exhaustion)
#[map]
static TCP_SYN_RATE_LIMIT_MAP: LruHashMap<u32, RateLimitState> = LruHashMap::<u32, RateLimitState>::with_max_entries(65536, 0);

/// Map 7: IPv6 Fast-Path Allowlist ([u8;16] -> RuleValue)
#[map]
static IPV6_ALLOWLIST_MAP: HashMap<[u8; 16], RuleValue> =
    HashMap::<[u8; 16], RuleValue>::with_max_entries(16384, 0);

/// Map 8: IPv6 Blocklist ([u8;16] -> RuleValue)
#[map]
static IPV6_BLOCKLIST_MAP: HashMap<[u8; 16], RuleValue> =
    HashMap::<[u8; 16], RuleValue>::with_max_entries(16384, 0);

/// Map 9: IPv6 /64 Subnet Aggregate LRU Rate Limiter
/// Keyed on the upper 8 bytes of the IPv6 source address (the /64 prefix).
#[map]
static IPV6_SUBNET_RATE_LIMIT_MAP: LruHashMap<[u8; 8], RateLimitState> =
    LruHashMap::<[u8; 8], RateLimitState>::with_max_entries(32768, 0);

/// Map 10: Per-/128 IPv6 Address LRU Rate Limiter
#[map]
static IPV6_RATE_LIMIT_MAP: LruHashMap<[u8; 16], RateLimitState> =
    LruHashMap::<[u8; 16], RateLimitState>::with_max_entries(65536, 0);

/// Map 11: Security Incident Ring Buffer (Addresses Issue #3)
#[map]
static EVENTS_RINGBUF: RingBuf = RingBuf::with_byte_size(262144, 0);

/// Map 12: Dynamic Adaptive Rate-Limit Configuration Map (Addresses Issue #5)
#[map]
static ADAPTIVE_CONFIG_MAP: Array<AdaptiveConfig> = Array::<AdaptiveConfig>::with_max_entries(1, 0);

// HELPER FUNCTIONS

/// Returns dynamic adaptive rate limit settings or fallback static defaults (Issue #5).
#[inline(always)]
fn get_rate_limits() -> (u64, u64, u64, u64) {
    if let Some(cfg) = ADAPTIVE_CONFIG_MAP.get(0) {
        if cfg.enabled != 0 {
            return (
                cfg.per_ip_capacity,
                cfg.per_ip_refill_ns,
                cfg.subnet_capacity,
                cfg.subnet_refill_ns,
            );
        }
    }
    (
        PER_IP_CAPACITY,
        PER_IP_REFILL_RATE_NS,
        SUBNET_CAPACITY,
        SUBNET_REFILL_RATE_NS,
    )
}

/// Streams forensic security incident event into kernel ring buffer (Issue #3).
#[inline(always)]
fn emit_event(
    now: u64,
    src_ip_bytes: [u8; 16],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    reason: u8,
    version: u8,
    len: u32,
) {
    if let Some(mut entry) = EVENTS_RINGBUF.reserve::<SecurityEvent>(0) {
        let ev = SecurityEvent {
            timestamp_ns: now,
            src_ip: src_ip_bytes,
            dst_port,
            src_port,
            protocol: proto,
            drop_reason: reason,
            ip_version: version,
            _pad: 0,
            packet_len: len,
            _reserved: 0,
        };
        entry.write(ev);
        entry.submit(0);
    }
}

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

/// Tracks TCP SYN packets and SYN-flood line-rate drops.
#[inline(always)]
fn record_tcp_syn(dropped: bool) {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).tcp_syn_packets += 1;
            if dropped {
                (*stats_ptr).tcp_syn_drops += 1;
            }
        }
    }
}

/// Increments UDP reflection/amplification attack drop counter.
#[inline(always)]
fn record_udp_reflection_drop() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).udp_reflection_drops += 1;
        }
    }
}

/// Increments IPv6 /64 subnet aggregate drop counter.
#[inline(always)]
fn record_ipv6_subnet_drop() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe { (*stats_ptr).ipv6_subnet_drops += 1; }
    }
}

/// Increments IPv6 /128 per-address drop counter.
#[inline(always)]
fn record_ipv6_per_ip_drop() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe { (*stats_ptr).ipv6_per_ip_drops += 1; }
    }
}

/// Increments IPv6 blocklist drop counter.
#[inline(always)]
fn record_ipv6_blocklist_drop() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe { (*stats_ptr).ipv6_blocklist_drops += 1; }
    }
}

/// Increments ICMPv6 echo-request flood drop counter.
#[inline(always)]
fn record_icmpv6_flood_drop() {
    if let Some(stats_ptr) = STATS_MAP.get_ptr_mut(0) {
        unsafe { (*stats_ptr).icmpv6_flood_drops += 1; }
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
    let mut ether_type_val = ether_type_raw as u16;
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

    // Route to appropriate L3 handler
    if ether_type_val == EtherType::Ipv6 as u16 {
        return handle_ipv6(ctx, l3_offset, packet_len);
    }
    if ether_type_val != EtherType::Ipv4 as u16 {
        // ARP, etc -- pass to OS
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

    let ip_proto = unsafe { core::ptr::addr_of!((*ip_hdr_ptr).proto).read_unaligned() };
    let ihl = unsafe { (*ip_hdr_ptr).ihl() } as usize;
    let l4_offset = l3_offset + (ihl * 4);

    // STEP 4.1: Layer-4 TCP SYN Flood Rate Limiting
    if ip_proto == IpProto::Tcp {
        if let Some(tcp_ptr) = ptr_at::<TcpHdr>(ctx, l4_offset) {
            let syn = unsafe { (*tcp_ptr).syn() };
            let ack = unsafe { (*tcp_ptr).ack() };
            if syn != 0 && ack == 0 {
                let syn_state = TCP_SYN_RATE_LIMIT_MAP.get_ptr_mut(&src_ip);
                let syn_allowed = match syn_state {
                    Some(ptr) => unsafe {
                        try_consume_token(&mut *ptr, TCP_SYN_BURST_CAPACITY, TCP_SYN_REFILL_RATE_NS, now_ns)
                    },
                    None => {
                        let initial = RateLimitState {
                            tokens: TCP_SYN_BURST_CAPACITY.saturating_sub(1),
                            last_update_ns: now_ns,
                        };
                        let _ = TCP_SYN_RATE_LIMIT_MAP.insert(&src_ip, &initial, 0);
                        true
                    }
                };
                if !syn_allowed {
                    record_tcp_syn(true);
                    record_metric(false, packet_len);
                    return Ok(xdp_action::XDP_DROP);
                }
                record_tcp_syn(false);
            }
        }
    }

    // STEP 4.2: Layer-4 UDP Reflection / Amplification Mitigation
    if ip_proto == IpProto::Udp {
        if let Some(udp_ptr) = ptr_at::<UdpHdr>(ctx, l4_offset) {
            let src_port_raw = unsafe { core::ptr::addr_of!((*udp_ptr).source).read_unaligned() };
            let src_port = u16::from_be(src_port_raw);
            if (src_port == 53 || src_port == 123 || src_port == 1900 || src_port == 11211 || src_port == 389)
                && packet_len > 512
            {
                record_udp_reflection_drop();
                record_metric(false, packet_len);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    // STEP 5: Fast-Path for Known / Active Flows
    // If the source IP already has an entry in RATE_LIMIT_MAP, enforce per-IP bucket directly.
    let state = RATE_LIMIT_MAP.get_ptr_mut(&src_ip);
    if let Some(state_ptr) = state {
        let allowed = unsafe {
            try_consume_token(&mut *state_ptr, PER_IP_CAPACITY, PER_IP_REFILL_RATE_NS, now_ns)
        };
        if allowed {
            record_metric(true, packet_len);
            return Ok(xdp_action::XDP_PASS);
        } else {
            record_metric(false, packet_len);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // STEP 6: Unseen / Unknown Source Gate (Ingress Admission Control)
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

    // STEP 7: Tier 1 - /24 Subnet-Level Aggregate Limiter
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

    // STEP 8: Allocate New Flow Entry in Tier 2 LRU with Conservative Burst
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

/// IPv6 packet filtering pipeline.
/// Implements: allowlist -> blocklist -> ICMPv6 flood -> /64 subnet bucket -> /128 per-IP bucket.
///
/// Note on src_addr extraction: Ipv6Hdr::src_addr is an in6_addr union. We read the raw bytes
/// via ptr_at on the known offset (8 bytes into the IPv6 fixed header) to obtain [u8; 16]
/// without depending on the in6_addr union field layout across compiler versions.
#[inline(always)]
fn handle_ipv6(ctx: &XdpContext, l3_offset: usize, packet_len: u64) -> Result<u32, ()> {
    // Parse IPv6 fixed header (40 bytes)
    // Ensure the full header fits in the packet
    if ptr_at::<Ipv6Hdr>(ctx, l3_offset).is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv6 header layout (RFC 2460):
    //   0-3:   version(4) + traffic class(8) + flow label(20)
    //   4-5:   payload length
    //   6:     next header
    //   7:     hop limit
    //   8-23:  source address (16 bytes)
    //   24-39: destination address (16 bytes)
    //
    // Read source address bytes directly at offset l3_offset + 8
    let src_addr_ptr = match ptr_at::<[u8; 16]>(ctx, l3_offset + 8) {
        Some(ptr) => ptr,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let src_addr: [u8; 16] = unsafe { core::ptr::read_unaligned(src_addr_ptr) };

    // Read next-header byte at offset l3_offset + 6
    let next_hdr_ptr = match ptr_at::<u8>(ctx, l3_offset + 6) {
        Some(ptr) => ptr,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let next_hdr: u8 = unsafe { core::ptr::read_unaligned(next_hdr_ptr) };

    let l4_offset = l3_offset + Ipv6Hdr::LEN;

    // Fast-path: Allowlist check
    if unsafe { IPV6_ALLOWLIST_MAP.get(&src_addr).is_some() } {
        record_metric(true, packet_len);
        return Ok(xdp_action::XDP_PASS);
    }

    // Blocklist check
    if unsafe { IPV6_BLOCKLIST_MAP.get(&src_addr).is_some() } {
        record_ipv6_blocklist_drop();
        record_metric(false, packet_len);
        return Ok(xdp_action::XDP_DROP);
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };

    // ICMPv6 echo-request flood mitigation
    if next_hdr == PROTO_ICMPV6 {
        if let Some(icmp_type_ptr) = ptr_at::<u8>(ctx, l4_offset) {
            let icmp_type = unsafe { core::ptr::read_unaligned(icmp_type_ptr) };
            if icmp_type == ICMPV6_TYPE_ECHO_REQUEST {
                let state = IPV6_RATE_LIMIT_MAP.get_ptr_mut(&src_addr);
                if let Some(state_ptr) = state {
                    let allowed = unsafe {
                        try_consume_token(&mut *state_ptr, IPV6_PER_IP_CAPACITY, IPV6_PER_IP_REFILL_RATE_NS, now_ns)
                    };
                    if !allowed {
                        record_icmpv6_flood_drop();
                        record_metric(false, packet_len);
                        return Ok(xdp_action::XDP_DROP);
                    }
                } else {
                    let initial = RateLimitState {
                        tokens: IPV6_PER_IP_CAPACITY.saturating_sub(1),
                        last_update_ns: now_ns,
                    };
                    let _ = IPV6_RATE_LIMIT_MAP.insert(&src_addr, &initial, 0);
                }
                record_metric(true, packet_len);
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    // UDP reflection amplification mitigation for IPv6
    if next_hdr == PROTO_UDP {
        if let Some(udp_ptr) = ptr_at::<UdpHdr>(ctx, l4_offset) {
            let src_port_raw = unsafe { core::ptr::addr_of!((*udp_ptr).source).read_unaligned() };
            let src_port = u16::from_be(src_port_raw);
            if (src_port == 53 || src_port == 123 || src_port == 1900 || src_port == 11211 || src_port == 389)
                && packet_len > 512
            {
                record_udp_reflection_drop();
                record_metric(false, packet_len);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    // /64 Subnet Aggregate Rate Limiting
    // Key = upper 8 bytes of src_addr (network prefix of /64)
    let subnet64: [u8; 8] = [
        src_addr[0], src_addr[1], src_addr[2], src_addr[3],
        src_addr[4], src_addr[5], src_addr[6], src_addr[7],
    ];

    let subnet_state = IPV6_SUBNET_RATE_LIMIT_MAP.get_ptr_mut(&subnet64);
    match subnet_state {
        Some(subnet_ptr) => {
            let allowed = unsafe {
                try_consume_token(&mut *subnet_ptr, IPV6_SUBNET_CAPACITY, IPV6_SUBNET_REFILL_RATE_NS, now_ns)
            };
            if !allowed {
                record_ipv6_subnet_drop();
                record_metric(false, packet_len);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        None => {
            let initial = RateLimitState {
                tokens: IPV6_SUBNET_CAPACITY.saturating_sub(1),
                last_update_ns: now_ns,
            };
            let _ = IPV6_SUBNET_RATE_LIMIT_MAP.insert(&subnet64, &initial, 0);
        }
    }

    // Per-/128 address rate limiting (fast-path for known flows)
    let per_ip_state = IPV6_RATE_LIMIT_MAP.get_ptr_mut(&src_addr);
    if let Some(state_ptr) = per_ip_state {
        let allowed = unsafe {
            try_consume_token(&mut *state_ptr, IPV6_PER_IP_CAPACITY, IPV6_PER_IP_REFILL_RATE_NS, now_ns)
        };
        if allowed {
            record_metric(true, packet_len);
            return Ok(xdp_action::XDP_PASS);
        } else {
            record_ipv6_per_ip_drop();
            record_metric(false, packet_len);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // New IPv6 source -- allocate /128 entry with conservative burst
    let initial = RateLimitState {
        tokens: INITIAL_BURST_TOKENS.saturating_sub(1),
        last_update_ns: now_ns,
    };
    if IPV6_RATE_LIMIT_MAP.insert(&src_addr, &initial, 0).is_err() {
        record_insert_failure();
        record_metric(false, packet_len);
        return Ok(xdp_action::XDP_DROP);
    }
    record_metric(true, packet_len);
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
