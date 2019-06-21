use std::io::Error;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr::copy_nonoverlapping;

use ebpf_core::{ffi, Map};

cfg_if! {
    if #[cfg(target_arch = "x86")] {
        pub const BPF_SYSCALL: libc::c_long = 357;
    } else if #[cfg(target_arch = "x86_64")] {
        pub const BPF_SYSCALL: libc::c_long = 321;
    } else if #[cfg(target_arch = "aarch64")] {
        pub const BPF_SYSCALL: libc::c_long = 280;
    } else {
        compile_error!("`ebpf-loader` does not support your arch.");
    }
}

pub unsafe fn create_map(map: &Map) -> Result<RawFd, Error> {
    let mut attr: ffi::bpf_attr = mem::zeroed();

    attr.__bindgen_anon_1.map_type = map.spec.ty as u32;
    attr.__bindgen_anon_1.key_size = map.spec.key_size;
    attr.__bindgen_anon_1.value_size = map.spec.value_size;
    attr.__bindgen_anon_1.max_entries = map.spec.capacity;
    attr.__bindgen_anon_1.map_flags = map.spec.flags.bits();
    attr.__bindgen_anon_1.map_ifindex = map.ifindex.unwrap_or_default();

    match map.inner_map_fd {
        Some(fd) if map.is_map_in_map() => {
            attr.__bindgen_anon_1.inner_map_fd = fd;
        }
        _ => {}
    }

    copy_nonoverlapping(
        map.name.as_bytes().as_ptr(),
        attr.__bindgen_anon_1.map_name.as_mut_ptr() as *mut _,
        map.name.len().min(ffi::BPF_OBJ_NAME_LEN as usize - 1),
    );

    bpf_syscall(ffi::bpf_cmd_BPF_MAP_CREATE, attr).map(|fd| fd as RawFd)
}

#[inline(always)]
unsafe fn bpf_syscall(cmd: ffi::bpf_cmd, attr: ffi::bpf_attr) -> Result<libc::c_long, Error> {
    let ret = libc::syscall(
        BPF_SYSCALL,
        cmd,
        &attr as *const _,
        mem::size_of::<ffi::bpf_attr>() as u32,
    );

    if ret < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(ret)
    }
}
