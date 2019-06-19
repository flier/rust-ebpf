/* automatically generated by rust-bindgen */

pub type __u64 = ::std::os::raw::c_ulonglong;
pub type u32 = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pt_regs {
    pub r15: ::std::os::raw::c_ulong,
    pub r14: ::std::os::raw::c_ulong,
    pub r13: ::std::os::raw::c_ulong,
    pub r12: ::std::os::raw::c_ulong,
    pub bp: ::std::os::raw::c_ulong,
    pub bx: ::std::os::raw::c_ulong,
    pub r11: ::std::os::raw::c_ulong,
    pub r10: ::std::os::raw::c_ulong,
    pub r9: ::std::os::raw::c_ulong,
    pub r8: ::std::os::raw::c_ulong,
    pub ax: ::std::os::raw::c_ulong,
    pub cx: ::std::os::raw::c_ulong,
    pub dx: ::std::os::raw::c_ulong,
    pub si: ::std::os::raw::c_ulong,
    pub di: ::std::os::raw::c_ulong,
    pub orig_ax: ::std::os::raw::c_ulong,
    pub ip: ::std::os::raw::c_ulong,
    pub cs: ::std::os::raw::c_ulong,
    pub flags: ::std::os::raw::c_ulong,
    pub sp: ::std::os::raw::c_ulong,
    pub ss: ::std::os::raw::c_ulong,
}
#[test]
fn bindgen_test_layout_pt_regs() {
    assert_eq!(
        ::std::mem::size_of::<pt_regs>(),
        168usize,
        concat!("Size of: ", stringify!(pt_regs))
    );
    assert_eq!(
        ::std::mem::align_of::<pt_regs>(),
        8usize,
        concat!("Alignment of ", stringify!(pt_regs))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r15 as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r15)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r14 as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r14)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r13 as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r13)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r12 as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r12)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).bp as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(bp)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).bx as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(bx)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r11 as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r11)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r10 as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r10)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r9 as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r9)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).r8 as *const _ as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(r8)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).ax as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(ax)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).cx as *const _ as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(cx)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).dx as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(dx)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).si as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(si)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).di as *const _ as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(di)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).orig_ax as *const _ as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(orig_ax)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).ip as *const _ as usize },
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(ip)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).cs as *const _ as usize },
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(cs)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).flags as *const _ as usize },
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).sp as *const _ as usize },
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(sp)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pt_regs>())).ss as *const _ as usize },
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(pt_regs),
            "::",
            stringify!(ss)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sock {
    _unused: [u8; 0],
}
#[doc = "\tstruct sk_buff - socket buffer"]
#[doc = "\t@next: Next buffer in list"]
#[doc = "\t@prev: Previous buffer in list"]
#[doc = "\t@tstamp: Time we arrived/left"]
#[doc = "\t@rbnode: RB tree node, alternative to next/prev for netem/tcp"]
#[doc = "\t@sk: Socket we are owned by"]
#[doc = "\t@dev: Device we arrived on/are leaving by"]
#[doc = "\t@cb: Control buffer. Free for use by every layer. Put private vars here"]
#[doc = "\t@_skb_refdst: destination entry (with norefcount bit)"]
#[doc = "\t@sp: the security path, used for xfrm"]
#[doc = "\t@len: Length of actual data"]
#[doc = "\t@data_len: Data length"]
#[doc = "\t@mac_len: Length of link layer header"]
#[doc = "\t@hdr_len: writable header length of cloned skb"]
#[doc = "\t@csum: Checksum (must include start/offset pair)"]
#[doc = "\t@csum_start: Offset from skb->head where checksumming should start"]
#[doc = "\t@csum_offset: Offset from csum_start where checksum should be stored"]
#[doc = "\t@priority: Packet queueing priority"]
#[doc = "\t@ignore_df: allow local fragmentation"]
#[doc = "\t@cloned: Head may be cloned (check refcnt to be sure)"]
#[doc = "\t@ip_summed: Driver fed us an IP checksum"]
#[doc = "\t@nohdr: Payload reference only, must not modify header"]
#[doc = "\t@pkt_type: Packet class"]
#[doc = "\t@fclone: skbuff clone status"]
#[doc = "\t@ipvs_property: skbuff is owned by ipvs"]
#[doc = "\t@tc_skip_classify: do not classify packet. set by IFB device"]
#[doc = "\t@tc_at_ingress: used within tc_classify to distinguish in/egress"]
#[doc = "\t@tc_redirected: packet was redirected by a tc action"]
#[doc = "\t@tc_from_ingress: if tc_redirected, tc_at_ingress at time of redirect"]
#[doc = "\t@peeked: this packet has been seen already, so stats have been"]
#[doc = "\t\tdone for it, don't do them again"]
#[doc = "\t@nf_trace: netfilter packet trace flag"]
#[doc = "\t@protocol: Packet protocol from driver"]
#[doc = "\t@destructor: Destruct function"]
#[doc = "\t@tcp_tsorted_anchor: list structure for TCP (tp->tsorted_sent_queue)"]
#[doc = "\t@_nfct: Associated connection, if any (with nfctinfo bits)"]
#[doc = "\t@nf_bridge: Saved data about a bridged frame - see br_netfilter.c"]
#[doc = "\t@skb_iif: ifindex of device we arrived on"]
#[doc = "\t@tc_index: Traffic control index"]
#[doc = "\t@hash: the packet hash"]
#[doc = "\t@queue_mapping: Queue mapping for multiqueue devices"]
#[doc = "\t@xmit_more: More SKBs are pending for this queue"]
#[doc = "\t@pfmemalloc: skbuff was allocated from PFMEMALLOC reserves"]
#[doc = "\t@ndisc_nodetype: router type (from link layer)"]
#[doc = "\t@ooo_okay: allow the mapping of a socket to a queue to be changed"]
#[doc = "\t@l4_hash: indicate hash is a canonical 4-tuple hash over transport"]
#[doc = "\t\tports."]
#[doc = "\t@sw_hash: indicates hash was computed in software stack"]
#[doc = "\t@wifi_acked_valid: wifi_acked was set"]
#[doc = "\t@wifi_acked: whether frame was acked on wifi or not"]
#[doc = "\t@no_fcs:  Request NIC to treat last 4 bytes as Ethernet FCS"]
#[doc = "\t@csum_not_inet: use CRC32c to resolve CHECKSUM_PARTIAL"]
#[doc = "\t@dst_pending_confirm: need to confirm neighbour"]
#[doc = "\t@napi_id: id of the NAPI struct this skb came from"]
#[doc = "\t@secmark: security marking"]
#[doc = "\t@mark: Generic packet mark"]
#[doc = "\t@vlan_proto: vlan encapsulation protocol"]
#[doc = "\t@vlan_tci: vlan tag control information"]
#[doc = "\t@inner_protocol: Protocol (encapsulation)"]
#[doc = "\t@inner_transport_header: Inner transport layer header (encapsulation)"]
#[doc = "\t@inner_network_header: Network layer header (encapsulation)"]
#[doc = "\t@inner_mac_header: Link layer header (encapsulation)"]
#[doc = "\t@transport_header: Transport layer header"]
#[doc = "\t@network_header: Network layer header"]
#[doc = "\t@mac_header: Link layer header"]
#[doc = "\t@tail: Tail pointer"]
#[doc = "\t@end: End pointer"]
#[doc = "\t@head: Head of buffer"]
#[doc = "\t@data: Data head pointer"]
#[doc = "\t@truesize: Buffer size"]
#[doc = "\t@users: User count - see {datagram,tcp}.c"]
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct sk_buff {
    pub _bindgen_opaque_blob: [u64; 29usize],
}
#[repr(C)]
#[repr(align(8))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_1 {
    pub _bindgen_opaque_blob: [u64; 3usize],
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct sk_buff__bindgen_ty_1__bindgen_ty_1 {
    pub _bindgen_opaque_blob: [u64; 3usize],
}
#[repr(C)]
#[repr(align(8))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1 {
    pub _bindgen_opaque_blob: u64,
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1>(),
        8usize,
        concat!(
            "Size of: ",
            stringify!(sk_buff__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1)
        )
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1>(),
        8usize,
        concat!(
            "Alignment of ",
            stringify!(sk_buff__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1)
        )
    );
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_1__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_1__bindgen_ty_1>(),
        24usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_1__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_1__bindgen_ty_1>(),
        8usize,
        concat!(
            "Alignment of ",
            stringify!(sk_buff__bindgen_ty_1__bindgen_ty_1)
        )
    );
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_1>(),
        24usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_1>(),
        8usize,
        concat!("Alignment of ", stringify!(sk_buff__bindgen_ty_1))
    );
}
#[repr(C)]
#[repr(align(8))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_2 {
    pub _bindgen_opaque_blob: u64,
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_2() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_2>(),
        8usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_2))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_2>(),
        8usize,
        concat!("Alignment of ", stringify!(sk_buff__bindgen_ty_2))
    );
}
#[repr(C)]
#[repr(align(8))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_3 {
    pub _bindgen_opaque_blob: [u64; 2usize],
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct sk_buff__bindgen_ty_3__bindgen_ty_1 {
    pub _bindgen_opaque_blob: [u64; 2usize],
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_3__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_3__bindgen_ty_1>(),
        16usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_3__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_3__bindgen_ty_1>(),
        8usize,
        concat!(
            "Alignment of ",
            stringify!(sk_buff__bindgen_ty_3__bindgen_ty_1)
        )
    );
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_3() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_3>(),
        16usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_3))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_3>(),
        8usize,
        concat!("Alignment of ", stringify!(sk_buff__bindgen_ty_3))
    );
}
#[repr(C)]
#[repr(align(4))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_4 {
    pub _bindgen_opaque_blob: u32,
}
#[repr(C)]
#[repr(align(2))]
#[derive(Debug, Copy, Clone)]
pub struct sk_buff__bindgen_ty_4__bindgen_ty_1 {
    pub _bindgen_opaque_blob: [u16; 2usize],
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_4__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_4__bindgen_ty_1>(),
        4usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_4__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_4__bindgen_ty_1>(),
        2usize,
        concat!(
            "Alignment of ",
            stringify!(sk_buff__bindgen_ty_4__bindgen_ty_1)
        )
    );
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_4() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_4>(),
        4usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_4))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_4>(),
        4usize,
        concat!("Alignment of ", stringify!(sk_buff__bindgen_ty_4))
    );
}
#[repr(C)]
#[repr(align(4))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_5 {
    pub _bindgen_opaque_blob: u32,
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_5() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_5>(),
        4usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_5))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_5>(),
        4usize,
        concat!("Alignment of ", stringify!(sk_buff__bindgen_ty_5))
    );
}
#[repr(C)]
#[repr(align(4))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_6 {
    pub _bindgen_opaque_blob: u32,
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_6() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_6>(),
        4usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_6))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_6>(),
        4usize,
        concat!("Alignment of ", stringify!(sk_buff__bindgen_ty_6))
    );
}
#[repr(C)]
#[repr(align(2))]
#[derive(Copy, Clone)]
pub union sk_buff__bindgen_ty_7 {
    pub _bindgen_opaque_blob: u16,
}
#[test]
fn bindgen_test_layout_sk_buff__bindgen_ty_7() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff__bindgen_ty_7>(),
        2usize,
        concat!("Size of: ", stringify!(sk_buff__bindgen_ty_7))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff__bindgen_ty_7>(),
        2usize,
        concat!("Alignment of ", stringify!(sk_buff__bindgen_ty_7))
    );
}
#[test]
fn bindgen_test_layout_sk_buff() {
    assert_eq!(
        ::std::mem::size_of::<sk_buff>(),
        232usize,
        concat!("Size of: ", stringify!(sk_buff))
    );
    assert_eq!(
        ::std::mem::align_of::<sk_buff>(),
        8usize,
        concat!("Alignment of ", stringify!(sk_buff))
    );
}
pub type bpf_user_pt_regs_t = pt_regs;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_perf_event_data {
    pub regs: bpf_user_pt_regs_t,
    pub sample_period: __u64,
}
#[test]
fn bindgen_test_layout_bpf_perf_event_data() {
    assert_eq!(
        ::std::mem::size_of::<bpf_perf_event_data>(),
        176usize,
        concat!("Size of: ", stringify!(bpf_perf_event_data))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_perf_event_data>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_perf_event_data))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_perf_event_data>())).regs as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_perf_event_data),
            "::",
            stringify!(regs)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_perf_event_data>())).sample_period as *const _ as usize
        },
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_perf_event_data),
            "::",
            stringify!(sample_period)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xdp_buff {
    pub data: *mut ::std::os::raw::c_void,
    pub data_end: *mut ::std::os::raw::c_void,
    pub data_meta: *mut ::std::os::raw::c_void,
    pub data_hard_start: *mut ::std::os::raw::c_void,
}
#[test]
fn bindgen_test_layout_xdp_buff() {
    assert_eq!(
        ::std::mem::size_of::<xdp_buff>(),
        32usize,
        concat!("Size of: ", stringify!(xdp_buff))
    );
    assert_eq!(
        ::std::mem::align_of::<xdp_buff>(),
        8usize,
        concat!("Alignment of ", stringify!(xdp_buff))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<xdp_buff>())).data as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(xdp_buff),
            "::",
            stringify!(data)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<xdp_buff>())).data_end as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(xdp_buff),
            "::",
            stringify!(data_end)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<xdp_buff>())).data_meta as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(xdp_buff),
            "::",
            stringify!(data_meta)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<xdp_buff>())).data_hard_start as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(xdp_buff),
            "::",
            stringify!(data_hard_start)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_sock_ops_kern {
    pub sk: *mut sock,
    pub op: u32,
    pub __bindgen_anon_1: bpf_sock_ops_kern__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops_kern__bindgen_ty_1 {
    pub reply: u32,
    pub replylong: [u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[test]
fn bindgen_test_layout_bpf_sock_ops_kern__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_sock_ops_kern__bindgen_ty_1>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_sock_ops_kern__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_sock_ops_kern__bindgen_ty_1>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_sock_ops_kern__bindgen_ty_1))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_sock_ops_kern__bindgen_ty_1>())).reply as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops_kern__bindgen_ty_1),
            "::",
            stringify!(reply)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_sock_ops_kern__bindgen_ty_1>())).replylong as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops_kern__bindgen_ty_1),
            "::",
            stringify!(replylong)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_sock_ops_kern() {
    assert_eq!(
        ::std::mem::size_of::<bpf_sock_ops_kern>(),
        32usize,
        concat!("Size of: ", stringify!(bpf_sock_ops_kern))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_sock_ops_kern>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_sock_ops_kern))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops_kern>())).sk as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops_kern),
            "::",
            stringify!(sk)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops_kern>())).op as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops_kern),
            "::",
            stringify!(op)
        )
    );
}
