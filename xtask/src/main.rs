//! xtask: Build orchestration for compiling eBPF programs.

use anyhow::{Context, Result};
use clap::Parser;
use std::process::Command as StdCommand;

#[derive(Parser)]
enum Command {
    /// Build the eBPF program target
    BuildEbpf,
}




fn main() -> Result<()> {
    let Command::BuildEbpf = Command::parse();

    println!("Compiling xdp-guard-ebpf for target bpfel-unknown-none...");

    let status = StdCommand::new("cargo")
        .args([
            "+nightly",
            "build",
            "--release",
            "--package",
            "xdp-guard-ebpf",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status()
        .context("Failed to execute cargo build for eBPF target")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed with exit code: {}", status);
    }

    println!("eBPF bytecode successfully generated at target/bpfel-unknown-none/release/xdp-guard-ebpf");
    Ok(())
}
