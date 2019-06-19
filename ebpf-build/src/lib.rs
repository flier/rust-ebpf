#[macro_use]
extern crate log;

use std::env;
use std::fs::File;
use std::io::{self, prelude::*};
use std::path::{Path, PathBuf};
use std::process::Command;

use ebpf_sys::BPF_MAXINSNS;
use failure::{format_err, Error, ResultExt};

const DEFAULT_OPT_LEVEL: usize = 3; // all optimizations
const DEFAULT_DEBUG_INFO: usize = 0; // no debug info at all
const DEFAULT_INLINE_THRESHOLD: usize = BPF_MAXINSNS as usize;
const DEFAULT_TARGET: &str = "bpf";

#[derive(Debug, Default)]
pub struct Builder {
    rustc: Option<PathBuf>,
    llc: Option<PathBuf>,
    deps: Vec<String>,
    profile: Option<String>,
    edition: Option<usize>,
    opt_level: Option<usize>,
    debug_info: Option<usize>,
    inline_threshold: Option<usize>,
    warn_opts: Vec<String>,
    allow_opts: Vec<String>,
    deny_opts: Vec<String>,
    forbid_opts: Vec<String>,
    codegen_opts: Vec<String>,
    target: Option<String>,
    kernel: Option<PathBuf>,
    out_dir: Option<PathBuf>,
}

impl Builder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn rustc<S: Into<PathBuf>>(mut self, rustc: S) -> Self {
        self.rustc = Some(rustc.into());
        self
    }

    pub fn llc<S: Into<PathBuf>>(mut self, llc: S) -> Self {
        self.llc = Some(llc.into());
        self
    }

    pub fn depends<I: IntoIterator<Item = S>, S: AsRef<str>>(mut self, pkgs: I) -> Self {
        for pkgid in pkgs {
            self.deps.push(pkgid.as_ref().to_owned());
        }

        self
    }

    pub fn profile<S: Into<String>>(mut self, profile: S) -> Self {
        self.profile = Some(profile.into());
        self
    }

    pub fn edition(mut self, edition: usize) -> Self {
        self.edition = Some(edition);
        self
    }

    pub fn opt_level(mut self, opt_level: usize) -> Self {
        self.opt_level = Some(opt_level);
        self
    }

    pub fn debug_info(mut self, debug_info: usize) -> Self {
        self.debug_info = Some(debug_info);
        self
    }

    pub fn inline_threshold(mut self, inline_threshold: usize) -> Self {
        self.inline_threshold = Some(inline_threshold);
        self
    }

    pub fn warn<S: Into<String>>(mut self, opt: S) -> Self {
        self.warn_opts.push(opt.into());
        self
    }

    pub fn allow<S: Into<String>>(mut self, opt: S) -> Self {
        self.allow_opts.push(opt.into());
        self
    }

    pub fn deny<S: Into<String>>(mut self, opt: S) -> Self {
        self.deny_opts.push(opt.into());
        self
    }

    pub fn forbid<S: Into<String>>(mut self, opt: S) -> Self {
        self.forbid_opts.push(opt.into());
        self
    }

    pub fn codegen<S: Into<String>>(mut self, opt: S) -> Self {
        self.codegen_opts.push(opt.into());
        self
    }

    pub fn target<S: Into<String>>(mut self, target: S) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn kernel<P: Into<PathBuf>>(mut self, kernel: P) -> Self {
        self.kernel = Some(kernel.into());
        self
    }

    pub fn out_dir<P: Into<PathBuf>>(mut self, out_dir: P) -> Self {
        self.out_dir = Some(out_dir.into());
        self
    }

    pub fn build(self) -> Result<PathBuf, Error> {
        let kernel_file = self
            .kernel
            .or_else(|| {
                env::var("CARGO_MANIFEST_DIR")
                    .ok()
                    .map(|s| PathBuf::from(s).join("src/lib.rs"))
            })
            .expect("CARGO_MANIFEST_DIR");
        let kernel_name = kernel_file.file_stem().expect("kernel").to_string_lossy();
        let out_dir = self
            .out_dir
            .or_else(|| env::var_os("OUT_DIR").map(|s| s.into()))
            .expect("OUT_DIR");
        let bc_file = out_dir.join(format!("{}.bc", kernel_name));
        let obj_file = out_dir.join(format!("{}.o", kernel_name));

        let metadata = cargo_metadata::MetadataCommand::new().exec()?;
        let profile = self
            .profile
            .or_else(|| env::var("PROFILE").ok())
            .expect("PROFILE");
        let target_dir = metadata.target_directory.join(profile);
        let deps_dir = target_dir.join("deps");

        // emit IR/bitcode
        let rustc = self
            .rustc
            .or_else(|| env::var_os("RUSTC").map(|s| s.into()))
            .unwrap_or_else(|| "rustc".into());

        let mut rustc = Command::new(rustc);

        rustc
            .arg(&kernel_file)
            .args(&[
                "--crate-type",
                "cdylib",
                "--verbose",
                "--emit=llvm-ir,llvm-bc",
            ])
            .arg("--codegen")
            .arg(format!(
                "debuginfo={}",
                self.debug_info.unwrap_or(DEFAULT_DEBUG_INFO)
            ))
            .arg("--codegen")
            .arg(format!(
                "opt-level={}",
                self.opt_level.unwrap_or(DEFAULT_OPT_LEVEL)
            ))
            .arg("--codegen")
            .arg(format!(
                "inline-threshold={}",
                self.inline_threshold.unwrap_or(DEFAULT_INLINE_THRESHOLD)
            ))
            .arg("--out-dir")
            .arg(&out_dir)
            .arg("-L")
            .arg(format!("dependency={}", deps_dir.to_string_lossy()));

        if let Some(edition) = self.edition {
            rustc.arg(format!("--edition={}", edition));
        }

        for opt in self.warn_opts {
            rustc.arg("--warn").arg(opt);
        }
        for opt in self.allow_opts {
            rustc.arg("--allow").arg(opt);
        }
        for opt in self.deny_opts {
            rustc.arg("--deny").arg(opt);
        }
        for opt in self.forbid_opts {
            rustc.arg("--forbid").arg(opt);
        }
        for opt in self.codegen_opts {
            rustc.arg("--codegen").arg(opt);
        }

        for pkgid in self
            .deps
            .into_iter()
            .chain(extract_extern_crate(&kernel_file)?)
        {
            rustc
                .arg("--extern")
                .arg(find_rlib(&deps_dir, &pkgid.replace("-", "_"))?);
        }

        rustc.run().context("compile eBPF kernel")?;

        // compile bitcode
        let llc = self
            .llc
            .or_else(|| env::var_os("LLC").map(|s| s.into()))
            .unwrap_or_else(|| "llc".into());

        Command::new(llc)
            .arg(format!(
                "-march={}",
                self.target.unwrap_or_else(|| DEFAULT_TARGET.to_owned())
            ))
            .arg("-filetype=obj")
            .arg(&bc_file)
            .arg("-o")
            .arg(&obj_file)
            .run()
            .map_err(
                |err| match err.find_root_cause().downcast_ref::<io::Error>() {
                    Some(ref err) if err.kind() == io::ErrorKind::NotFound => {
                        format_err!("command `llc` not found in path, please install LLVM first or point to with `LLC=<path>`")
                    }
                    _ => err.context("generate eBPF kernel").into(),
                },
            )?;

        println!("cargo:rerun-if-changed={}", kernel_file.to_string_lossy());
        println!("cargo:rerun-if-env-changed=LLC");
        println!(
            "cargo:rustc-env={}={}",
            kernel_name.to_uppercase(),
            obj_file.to_string_lossy()
        );

        Ok(obj_file)
    }
}

fn extract_extern_crate(kernel_file: &Path) -> Result<impl Iterator<Item = String>, Error> {
    let mut file = File::open(kernel_file)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let file = syn::parse_file(&content)?;

    Ok(file.items.into_iter().flat_map(|item| {
        if let syn::Item::ExternCrate(syn::ItemExternCrate { ident, .. }) = item {
            Some(ident.to_string())
        } else {
            None
        }
    }))
}

fn find_rlib(dir: &Path, name: &str) -> Result<String, Error> {
    let pattern = dir.join(format!("lib{}-*.rlib", name));
    let mut filenames = glob::glob(&pattern.to_string_lossy())?.collect::<Result<Vec<_>, _>>()?;

    filenames.sort_by_cached_key(|filename| {
        filename
            .metadata()
            .expect("metadata")
            .modified()
            .expect("modified time")
    });

    filenames
        .pop()
        .map(|filename| format!("{}={}", name, filename.to_string_lossy()))
        .ok_or_else(|| format_err!("rlib `{}` not found", name))
}

trait Runable {
    type Output;
    type Error;

    fn run(&mut self) -> Result<Self::Output, Self::Error>;
}

impl Runable for Command {
    type Output = ();
    type Error = Error;

    fn run(&mut self) -> Result<(), Error> {
        debug!("run: {:?}", self);

        let output = self.output()?;

        if output.status.success() {
            if !output.stdout.is_empty() {
                debug!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
            }

            Ok(())
        } else {
            debug!("status: {}", output.status);

            if !output.stderr.is_empty() {
                warn!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
            }

            Err(format_err!("run command failed, status={}", output.status))
        }
    }
}
