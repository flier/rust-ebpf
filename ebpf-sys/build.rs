use failure::{Error, ResultExt};

#[cfg(feature = "gen")]
fn generate_binding_file() -> Result<(), Error> {
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::path::PathBuf;

    use failure::{err_msg, Fail};

    let out_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| err_msg("missed `OUT_DIR`"))?);

    eprintln!("generate binding files to {:?}", out_dir);

    bindgen::Builder::default()
        .header("src/raw.h")
        .clang_args(&[
            "-Ilibbpf",
            "-Ilibbpf/src",
            "-Ilibbpf/include",
            "-Ilibbpf/include/uapi",
        ])
        .whitelist_var("(BPF|LIBBPF|bpf)_.*")
        .whitelist_type("(bpf|libbpf|xdp|sk)_.*")
        .whitelist_function("(bpf|btf)_.*")
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .impl_debug(true)
        .impl_partialeq(true)
        .generate()
        .map_err(|_| err_msg("generate eBPF bindings"))?
        .write_to_file(out_dir.join("raw.rs"))
        .context("write eBPF bindings")?;

    if cfg!(target_os = "linux") {
        let release = unsafe {
            let mut buf: libc::utsname = mem::zeroed();

            if libc::uname(&mut buf) != 0 {
                return Err(io::Error::last_os_error()).map_err(|err| err.context("uname").into());
            }

            CStr::from_ptr(buf.release.as_ptr() as *const _)
                .to_str()?
                .to_owned()
        };

        eprintln!("generate binding file for kernel {}", release);

        let build_dir = PathBuf::from("/lib/modules").join(&release).join("build");

        if !build_dir.is_dir() {
            panic!("Please install `linux-headers-{}` first", release);
        }

        let arch = if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            "x86"
        } else if cfg!(target_arch = "mips") {
            "mips"
        } else if cfg!(any(target_arch = "powerpc", target_arch = "powerpc64")) {
            "powerpc"
        } else if cfg!(target_arch = "arm") {
            "arm"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            panic!("unsupport arch")
        };

        let arch_dir = build_dir.join("arch").join(arch);

        let macros = {
            let mut v = vec!["__KERNEL__"];

            if cfg!(target_pointer_width = "64") {
                v.push("CONFIG_64BIT=1");
            }

            v.into_iter()
                .map(|name| format!("-D{}", name))
                .collect::<Vec<_>>()
        };

        eprintln!("macros: {:#?}", &macros);

        bindgen::Builder::default()
            .header("src/kernel.h")
            .clang_args(macros)
            .clang_args(&[
                format!("-I{}", arch_dir.join("include").to_string_lossy()),
                format!("-I{}", arch_dir.join("include/generated").to_string_lossy()),
                format!("-I{}", build_dir.join("include").to_string_lossy()),
                format!(
                    "-I{}",
                    build_dir.join("include/generated").to_string_lossy()
                ),
            ])
            .whitelist_type("(bpf_sock_ops_kern|bpf_perf_event_data|sk_buff|xdp_buff|pt_regs)")
            .opaque_type("sk_buff|sock")
            .ignore_functions()
            .derive_debug(true)
            .derive_default(true)
            .derive_partialeq(true)
            .impl_debug(true)
            .impl_partialeq(true)
            .generate()
            .map_err(|_| err_msg("generate kernel bindings"))?
            .write_to_file(out_dir.join("kernel.rs"))
            .context("write kernel bindings")?;
    }

    Ok(())
}

#[cfg(not(feature = "gen"))]
fn generate_binding_file() -> Result<(), Error> {
    Ok(())
}

fn main() -> Result<(), Error> {
    generate_binding_file().context("generate binding files")?;

    println!("cargo:rerun-if-changed=src/raw.h");
    println!("cargo:rerun-if-changed=src/kernel.h");

    Ok(())
}
