//! xdp-guard-common: Shared types and data contracts between eBPF kernel space and Rust userspace.
//!
//! Why this crate exists:
//! In eBPF programming, the kernel code (running in restricted bytecode inside Linux) and
//! the userspace application (controlling the firewall from the terminal) communicate
//! using shared memory regions called "BPF Maps".
//! For both sides to understand the memory layout identically without subtle alignment bugs,
//! all shared structs must have a fixed, explicit memory layout (`#[repr(C)]`).
//!
//! Notice: All fields are strictly 8-byte aligned (or padded) so that `bytemuck::Pod`
//! can safely cast memory between user and kernel space without uninitialized padding bytes!

#![no_std]

use bytemuck::{Pod, Zeroable};

/// Represents the decision/action taken on an incoming network packet.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Allow the packet to continue normal Linux network stack processing.
    Pass = 0,
    /// Immediately discard the packet at the NIC driver layer (line-rate drop).
    Drop = 1,
}

/// Dynamic filtering rule matching an IPv4 address.
///
/// Packed into eBPF Hash Maps (`BLOCKLIST_MAP` and `ALLOWLIST_MAP`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
pub struct RuleValue {
    /// Action to take when this IP matches (0 = Pass, 1 = Drop).
    pub action: u32,
    /// Explicit padding to ensure 8-byte alignment for 64-bit timestamps.
    pub _pad: u32,
    /// Unix timestamp (in seconds or nanoseconds) when this rule was added.
    pub created_at: u64,
    /// Optional expiration duration in seconds (0 = permanent rule).
    pub ttl_secs: u64,
}

/// Token Bucket State for per-IP rate limiting.
///
/// The Token Bucket algorithm allows bursty traffic up to a maximum limit,
/// while maintaining a smooth average packet rate over time.
/// Everything happens directly inside the kernel with zero userspace context switches!
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct RateLimitState {
    /// Number of tokens currently available in the bucket.
    pub tokens: u64,
    /// Kernel monotonic timestamp (in nanoseconds via `bpf_ktime_get_ns`) of the last packet arrival.
    pub last_update_ns: u64,
}

/// Per-CPU or Global packet counters for metrics and real-time observability.
///
/// Userspace continuously polls these statistics to display throughput and drop rates.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, Pod, Zeroable)]
pub struct PacketStats {
    /// Total number of packets allowed through to the OS network stack.
    pub passed_packets: u64,
    /// Total bytes passed.
    pub passed_bytes: u64,
    /// Total packets dropped by blocklists or rate limiters.
    pub dropped_packets: u64,
    /// Total bytes dropped.
    pub dropped_bytes: u64,
    /// Total map insertion failures under extreme state table exhaustion.
    pub map_insert_failures: u64,
    /// Total packets dropped due to new-source admission budget exhaustion under spoofed floods.
    pub admission_drops: u64,
    /// Total packets dropped by /24 subnet aggregate rate limiting.
    pub subnet_drops: u64,
    /// Total TCP SYN packets received.
    pub tcp_syn_packets: u64,
    /// Total TCP SYN flood packets dropped at line-rate.
    pub tcp_syn_drops: u64,
    /// Total UDP reflection/amplification flood packets dropped.
    pub udp_reflection_drops: u64,
    /// Total IPv6 packets dropped by /64 subnet aggregate rate limiting.
    pub ipv6_subnet_drops: u64,
    /// Total IPv6 /128 per-address packets dropped.
    pub ipv6_per_ip_drops: u64,
    /// Total IPv6 packets dropped by blocklist.
    pub ipv6_blocklist_drops: u64,
    /// Total IPv6 ICMPv6 flood packets dropped.
    pub icmpv6_flood_drops: u64,
}

// Implement aya::Pod marker trait so userspace Aya can read/write these structs to BPF maps
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketStats {}

/// High-fidelity forensic event captured by the XDP engine on dropped or throttled packets.
///
/// Streamed from the Linux kernel to userspace via `BPF_MAP_TYPE_RINGBUF` (Addresses Issue #3).
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable, PartialEq, Eq)]
pub struct SecurityEvent {
    /// Monotonic timestamp in nanoseconds when packet arrived (bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// Source IP address bytes (IPv4 in lower 4 bytes or full IPv6).
    pub src_ip: [u8; 16],
    /// Destination port (host byte order).
    pub dst_port: u16,
    /// Source port (host byte order).
    pub src_port: u16,
    /// IP Protocol (6 = TCP, 17 = UDP, 58 = ICMPv6, etc.).
    pub protocol: u8,
    /// Drop reason code from `drop_reasons`.
    pub drop_reason: u8,
    /// IP Version (4 or 6).
    pub ip_version: u8,
    /// Explicit padding byte for 8-byte alignment.
    pub _pad: u8,
    /// Total packet length in wire bytes.
    pub packet_len: u32,
    /// Reserved for future flags / telemetry.
    pub _reserved: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecurityEvent {}

/// Security drop reason constants for `SecurityEvent`.
pub mod drop_reasons {
    pub const BLOCKLIST: u8 = 1;
    pub const PER_IP_RATE_LIMIT: u8 = 2;
    pub const SUBNET_RATE_LIMIT: u8 = 3;
    pub const TCP_SYN_FLOOD: u8 = 4;
    pub const UDP_REFLECTION: u8 = 5;
    pub const ADMISSION_EXHAUSTION: u8 = 6;
    pub const IPV6_ICMPV6_FLOOD: u8 = 7;

    pub fn as_str(reason: u8) -> &'static str {
        match reason {
            BLOCKLIST => "BLOCKLIST",
            PER_IP_RATE_LIMIT => "PER_IP_RATE_LIMIT",
            SUBNET_RATE_LIMIT => "SUBNET_RATE_LIMIT",
            TCP_SYN_FLOOD => "TCP_SYN_FLOOD",
            UDP_REFLECTION => "UDP_REFLECTION",
            ADMISSION_EXHAUSTION => "ADMISSION_EXHAUSTION",
            IPV6_ICMPV6_FLOOD => "IPV6_ICMPV6_FLOOD",
            _ => "UNKNOWN",
        }
    }
}

/// Dynamic rate-limiting configuration for adaptive threshold auto-tuning.
///
/// Written by userspace auto-tuning daemon into an eBPF Array map without reloading bytecode
/// (Addresses Issue #5).
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable, PartialEq, Eq)]
pub struct AdaptiveConfig {
    /// Dynamic per-IP token burst ceiling.
    pub per_ip_capacity: u64,
    /// Dynamic per-IP refill interval in nanoseconds (1 token every N ns).
    pub per_ip_refill_ns: u64,
    /// Dynamic subnet token burst ceiling.
    pub subnet_capacity: u64,
    /// Dynamic subnet refill interval in nanoseconds.
    pub subnet_refill_ns: u64,
    /// Observed baseline packet rate in pps (e.g. p95 across recent window).
    pub baseline_pps: u64,
    /// Scaling multiplier in thousandths (e.g. 3000 = 3.0x threshold above baseline).
    pub multiplier_x1000: u32,
    /// 1 = adaptive threshold active; 0 = static mode.
    pub enabled: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AdaptiveConfig {}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            per_ip_capacity: 1000,
            per_ip_refill_ns: 1_000_000, // 1,000 pps
            subnet_capacity: 5000,
            subnet_refill_ns: 200_000, // 5,000 pps
            baseline_pps: 500,
            multiplier_x1000: 3000, // 3.0x
            enabled: 0,
        }
    }
}

impl AdaptiveConfig {
    /// Calculate new dynamic rate limits from an observed baseline PPS and user-defined constraints.
    pub fn compute_tuned(
        baseline_pps: u64,
        multiplier: f32,
        min_pps: u64,
        max_pps: u64,
    ) -> Self {
        let scaled_pps = ((baseline_pps as f64) * (multiplier as f64)) as u64;
        let clamped_pps = if scaled_pps < min_pps {
            min_pps
        } else if scaled_pps > max_pps {
            max_pps
        } else {
            scaled_pps
        };
        let clamped_pps = if clamped_pps == 0 { 1 } else { clamped_pps };

        let refill_ns = 1_000_000_000 / clamped_pps;
        let capacity = if clamped_pps / 2 < 10 { 10 } else { clamped_pps / 2 };

        Self {
            per_ip_capacity: capacity,
            per_ip_refill_ns: refill_ns,
            subnet_capacity: capacity * 5,
            subnet_refill_ns: if refill_ns / 5 == 0 { 1 } else { refill_ns / 5 },
            baseline_pps,
            multiplier_x1000: (multiplier * 1000.0) as u32,
            enabled: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_memory_layout() {
        assert_eq!(core::mem::size_of::<SecurityEvent>(), 40);
        assert_eq!(core::mem::align_of::<SecurityEvent>(), 8);

        let event = SecurityEvent {
            timestamp_ns: 123456789,
            src_ip: [192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_port: 80,
            src_port: 44123,
            protocol: 6,
            drop_reason: drop_reasons::TCP_SYN_FLOOD,
            ip_version: 4,
            _pad: 0,
            packet_len: 64,
            _reserved: 0,
        };

        let bytes = bytemuck::bytes_of(&event);
        assert_eq!(bytes.len(), 40);
        let decoded: &SecurityEvent = bytemuck::from_bytes(bytes);
        assert_eq!(decoded.timestamp_ns, 123456789);
        assert_eq!(decoded.dst_port, 80);
        assert_eq!(decoded.drop_reason, drop_reasons::TCP_SYN_FLOOD);
        assert_eq!(drop_reasons::as_str(decoded.drop_reason), "TCP_SYN_FLOOD");
    }

    #[test]
    fn test_adaptive_config_compute_tuned() {
        assert_eq!(core::mem::size_of::<AdaptiveConfig>(), 48);
        assert_eq!(core::mem::align_of::<AdaptiveConfig>(), 8);

        // Baseline: 1000 pps, Multiplier: 3.0x -> 3000 pps
        let cfg = AdaptiveConfig::compute_tuned(1000, 3.0, 500, 50000);
        assert_eq!(cfg.enabled, 1);
        assert_eq!(cfg.baseline_pps, 1000);
        assert_eq!(cfg.multiplier_x1000, 3000);
        assert_eq!(cfg.per_ip_refill_ns, 1_000_000_000 / 3000);
        assert_eq!(cfg.per_ip_capacity, 1500);

        // Clamping to floor
        let cfg_floor = AdaptiveConfig::compute_tuned(10, 2.0, 1000, 50000);
        assert_eq!(cfg_floor.per_ip_refill_ns, 1_000_000); // 1000 pps floor
        assert_eq!(cfg_floor.per_ip_capacity, 500);

        // Clamping to ceiling
        let cfg_ceil = AdaptiveConfig::compute_tuned(100_000, 3.0, 1000, 50_000);
        assert_eq!(cfg_ceil.per_ip_refill_ns, 1_000_000_000 / 50_000);
        assert_eq!(cfg_ceil.per_ip_capacity, 25_000);
    }
}
