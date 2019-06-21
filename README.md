# rust-ebpf

`rust-ebpf` is a experimental project that provides a toolchain to compile, load and run eBPF program.

## Build

`rust-ebpf` support to compile rust code to eBPF object.

First, add the `ebpf-build` crate to your `Cargo.toml`.

```toml
[build-dependencies]
ebpf-build = "0.1"
```

Then, compile and build the kernel file to eBPF object.

```rust
extern crate ebpf_build;

fn main() {
    ebpf_build::Builder::new().build().expect("build kernel");
}
```

Then, the generated kernel file will be point by the `KERNEL` envrionment variable.

```rust
const KERNEL: &[u8] = include_bytes!(env!("KERNEL"));
```

**Note:** Build eBPF object need install `llvm` first, and you can point to `llc` command with `LLC` envrionment variable.

## Load

`rust-ebpf` support to load the eBPF programs from a ELF file.

First, add the `ebpf-loader` crate to your `Cargo.toml`.

```toml
[dependencies]
ebpf-loader = "0.1"
```

Then, load or parse the ELF file for programs.

```rust
let obj = ebpf_loader::parse(KERNEL)?;
```

## Run

## Reference

* [PoC: compiling to eBPF from Rust](http://unhandledexpression.com/general/rust/2018/02/02/poc-compiling-to-ebpf-from-rust.html)
