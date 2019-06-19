#[cfg(feature = "gen")]
fn prepare_binding_file() {
    use std::path::PathBuf;

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));

    bindgen::Builder::default()
        .header("src/raw.h")
        .clang_args(&[
            "-Ilibbpf",
            "-Ilibbpf/src",
            "-Ilibbpf/include",
            "-Ilibbpf/include/uapi",
        ])
        .whitelist_var("(BPF|LIBBPF|bpf)_.*")
        .whitelist_type("(bpf|libbpf|xdp)_.*")
        .whitelist_function("(bpf|btf)_.*")
        .generate()
        .expect("generate bindings")
        .write_to_file(out_dir.join("raw.rs"))
        .expect("write bindings")
}

#[cfg(not(feature = "gen"))]
fn prepare_binding_file() {}

fn main() {
    prepare_binding_file()
}
