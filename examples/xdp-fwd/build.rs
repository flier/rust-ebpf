use ebpf_build::Builder;

fn main() {
    pretty_env_logger::init();

    Builder::new()
        .kernel("src/kernel.rs")
        .build()
        .expect("build eBPF kernel");
}
