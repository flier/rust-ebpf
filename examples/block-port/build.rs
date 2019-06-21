extern crate ebpf_build;

fn main() {
    ebpf_build::Builder::new().build().expect("build kernel");
}
