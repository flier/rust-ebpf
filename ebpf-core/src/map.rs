use core::convert::TryFrom;
use core::ops::{Deref, DerefMut};

use failure::{format_err, Error};

use crate::ffi;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, TryFrom)]
pub enum Type {
    Unspec = ffi::bpf_map_type_BPF_MAP_TYPE_UNSPEC,
    Hash = ffi::bpf_map_type_BPF_MAP_TYPE_HASH,
    Array = ffi::bpf_map_type_BPF_MAP_TYPE_ARRAY,
    ProgArray = ffi::bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY,
    PerfEventArray = ffi::bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    PerCpuHash = ffi::bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH,
    PerCpuArray = ffi::bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY,
    StackTrace = ffi::bpf_map_type_BPF_MAP_TYPE_STACK_TRACE,
    CGroupArray = ffi::bpf_map_type_BPF_MAP_TYPE_CGROUP_ARRAY,
    LruHash = ffi::bpf_map_type_BPF_MAP_TYPE_LRU_HASH,
    LruPerCpuHash = ffi::bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH,
    LpmTrie = ffi::bpf_map_type_BPF_MAP_TYPE_LPM_TRIE,
    ArrayOfMaps = ffi::bpf_map_type_BPF_MAP_TYPE_ARRAY_OF_MAPS,
    HashOfMaps = ffi::bpf_map_type_BPF_MAP_TYPE_HASH_OF_MAPS,
    DevMap = ffi::bpf_map_type_BPF_MAP_TYPE_DEVMAP,
    SockMap = ffi::bpf_map_type_BPF_MAP_TYPE_SOCKMAP,
    CpuMap = ffi::bpf_map_type_BPF_MAP_TYPE_CPUMAP,
    XskMap = ffi::bpf_map_type_BPF_MAP_TYPE_XSKMAP,
    SockHash = ffi::bpf_map_type_BPF_MAP_TYPE_SOCKHASH,
    CGroupStorage = ffi::bpf_map_type_BPF_MAP_TYPE_CGROUP_STORAGE,
    ReusePortSockArray = ffi::bpf_map_type_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    PerCpuCGroupStorage = ffi::bpf_map_type_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    Queue = ffi::bpf_map_type_BPF_MAP_TYPE_QUEUE,
    Stack = ffi::bpf_map_type_BPF_MAP_TYPE_STACK,
    SkStorage = ffi::bpf_map_type_BPF_MAP_TYPE_SK_STORAGE,
}

impl Default for Type {
    fn default() -> Self {
        Type::Unspec
    }
}

#[derive(Debug)]
pub struct Map {
    pub name: String,
    pub offset: usize,
    pub ifindex: Option<u32>,
    pub inner_map_fd: Option<u32>,
    pub spec: Spec,
}

#[derive(Debug)]
pub struct Spec {
    pub ty: Type,
    pub key_size: u32,
    pub value_size: u32,
    pub capacity: u32,
    pub flags: Flags,
}

bitflags! {
    pub struct Flags: u32 {
        const NO_PREALLOC = ffi::BPF_F_NO_PREALLOC;
        const NO_COMMON_LRU = ffi::BPF_F_NO_COMMON_LRU;
        /// Specify numa node during map creation
        const NUMA_NODE = ffi::BPF_F_NUMA_NODE;
        const RDONLY = ffi::BPF_F_RDONLY;
        const WRONLY = ffi::BPF_F_WRONLY;
        /// Flag for stack_map, store build_id+offset instead of pointer
        const STACK_BUILD_ID = ffi::BPF_F_STACK_BUILD_ID;
        /// Zero-initialize hash function seed. This should only be used for testing.
        const ZERO_SEED = ffi::BPF_F_ZERO_SEED;
        const RDONLY_PROG = ffi::BPF_F_RDONLY_PROG;
        const WRONLY_PROG = ffi::BPF_F_WRONLY_PROG;
    }
}

impl Spec {
    pub fn is_map_in_map(&self) -> bool {
        self.ty == Type::ArrayOfMaps || self.ty == Type::HashOfMaps
    }
}

impl Deref for Map {
    type Target = Spec;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.spec
    }
}

impl DerefMut for Map {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.spec
    }
}

impl Map {
    pub fn with_def<S: Into<String>>(
        name: S,
        offset: usize,
        ifindex: Option<u32>,
        def: &ffi::bpf_map_def,
    ) -> Result<Self, Error> {
        let ty = Type::try_from(def.type_)
            .map_err(|_| format_err!("unexpected map type: {}", def.type_))?;

        Ok(Map {
            name: name.into(),
            offset,
            ifindex,
            inner_map_fd: None,
            spec: Spec {
                ty,
                key_size: def.key_size,
                value_size: def.value_size,
                capacity: def.max_entries,
                flags: Flags::from_bits_truncate(def.map_flags),
            },
        })
    }

    pub fn with_spec<S: Into<String>>(
        name: S,
        offset: usize,
        ifindex: Option<u32>,
        spec: Spec,
    ) -> Self {
        Map {
            name: name.into(),
            offset,
            ifindex,
            inner_map_fd: None,
            spec,
        }
    }
}
