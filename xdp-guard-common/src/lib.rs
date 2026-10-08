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
}

// Implement aya::Pod marker trait so userspace Aya can read/write these structs to BPF maps
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketStats {}
