# Summary
This a personal project to grasp a better understanding of TCP connections using AF_XDP. The last time I made a program using AF_XDP was about multicloning and redirecting UDP packets. This time I want the load balancer to include the following: 
- Stop syn flood
- Stop connections using a blocklist (surely I will block the IP's from the kernel space).
- Implement a backend that controls remotely the blocklist and also fetch statistics using Prometheus.
- Implement Prometheus.
- Implement NAT Table to control connections.
- Send the TCP packets to different backends and handle the connections from the AF_XDP program deleting from the list of open connections those that are going to close.
- Filter ports that are not going to port 80 or 443.

## Recommendations

I'm open to receive any feedback.

# How to run load-balancer

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package load-balancer --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/load-balancer` can be
copied to a Linux server or VM and run there.
