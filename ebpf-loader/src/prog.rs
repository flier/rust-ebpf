use ebpf_core::{Attach, Type};

#[derive(Debug)]
struct Section {
    prefix: &'static str,
    prog_type: Type,
    expected_attach_type: Option<Attach>,
    attach_type: Option<Attach>,
}

impl Section {
    const fn new(
        prefix: &'static str,
        prog_type: Type,
        expected_attach_type: Option<Attach>,
        attach_type: Option<Attach>,
    ) -> Section {
        Section {
            prefix,
            prog_type,
            expected_attach_type,
            attach_type,
        }
    }

    fn by_name(name: &str) -> Option<&Self> {
        SECTION_NAMES
            .iter()
            .find(|sec| name.starts_with(sec.prefix))
    }
}

pub fn prog_type_by_name(name: &str) -> Option<(Type, Option<Attach>)> {
    Section::by_name(name).map(|sec| (sec.prog_type, sec.expected_attach_type))
}

pub fn attach_type_by_name(name: &str) -> Option<Attach> {
    Section::by_name(name).and_then(|sec| sec.attach_type)
}

/// Programs that can NOT be attached.
const fn prog_sec(prefix: &'static str, prog_type: Type) -> Section {
    Section::new(prefix, prog_type, None, None)
}

/// Programs that can be attached.
const fn aprog_sec(prefix: &'static str, prog_type: Type, attach_type: Attach) -> Section {
    Section::new(prefix, prog_type, None, Some(attach_type))
}

/// Programs that must specify expected attach type at load time.
const fn eaprog_sec(prefix: &'static str, prog_type: Type, attach_type: Attach) -> Section {
    Section::new(prefix, prog_type, Some(attach_type), Some(attach_type))
}

lazy_static! {
    static ref SECTION_NAMES: Vec<Section> = vec![
        prog_sec("socket", Type::SocketFilter),
        prog_sec("kprobe/", Type::KProbe),
        prog_sec("kretprobe/", Type::KProbe),
        prog_sec("classifier", Type::SchedClass),
        prog_sec("action", Type::SchedAction),
        prog_sec("tracepoint/", Type::TracePoint),
        prog_sec("raw_tracepoint/", Type::RawTracePoint),
        prog_sec("xdp", Type::XDP),
        prog_sec("perf_event", Type::PerfEvent),
        prog_sec("lwt_in", Type::LwtIn),
        prog_sec("lwt_out", Type::LwtOut),
        prog_sec("lwt_xmit", Type::LwtXmit),
        prog_sec("lwt_seg6local", Type::LwtSeg6Local),
        aprog_sec(
            "cgroup_skb/ingress",
            Type::CGroupSkb,
            Attach::CGroupInetIngress
        ),
        aprog_sec(
            "cgroup_skb/egress",
            Type::CGroupSkb,
            Attach::CGroupInetEgress,
        ),
        prog_sec("cgroup/skb", Type::CGroupSkb),
        aprog_sec(
            "cgroup/sock",
            Type::CGroupSock,
            Attach::CGroupInetSockCreate
        ),
        eaprog_sec(
            "cgroup/post_bind4",
            Type::CGroupSock,
            Attach::CGroupInet4PostBind
        ),
        eaprog_sec(
            "cgroup/post_bind6",
            Type::CGroupSock,
            Attach::CGroupInet6PostBind
        ),
        aprog_sec("cgroup/dev", Type::CGroupDevice, Attach::CGroupDevice),
        aprog_sec("sockops", Type::SockOps, Attach::CGroupSockOps),
        aprog_sec(
            "sk_skb/stream_parser",
            Type::SkSkb,
            Attach::SkSkbStreamParser,
        ),
        aprog_sec(
            "sk_skb/stream_verdict",
            Type::SkSkb,
            Attach::SkSkbStreamVerdict,
        ),
        prog_sec("sk_skb", Type::SkSkb),
        aprog_sec("sk_msg", Type::SkMsg, Attach::SkMsgVerdict),
        aprog_sec("lirc_mode2", Type::LircMode2, Attach::LircMode2),
        aprog_sec("flow_dissector", Type::FlowDissector, Attach::FlowDissector,),
        eaprog_sec(
            "cgroup/bind4",
            Type::CGroupSockAddr,
            Attach::CGroupInet4Bind,
        ),
        eaprog_sec(
            "cgroup/bind6",
            Type::CGroupSockAddr,
            Attach::CGroupInet6Bind,
        ),
        eaprog_sec(
            "cgroup/connect4",
            Type::CGroupSockAddr,
            Attach::CGroupInet4Connect,
        ),
        eaprog_sec(
            "cgroup/connect6",
            Type::CGroupSockAddr,
            Attach::CGroupInet6Connect,
        ),
        eaprog_sec(
            "cgroup/sendmsg4",
            Type::CGroupSockAddr,
            Attach::CGroupUdp4Sendmsg,
        ),
        eaprog_sec(
            "cgroup/sendmsg6",
            Type::CGroupSockAddr,
            Attach::CGroupUdp6Sendmsg,
        ),
        eaprog_sec(
            "cgroup/recvmsg4",
            Type::CGroupSockAddr,
            Attach::CGroupUdp4Recvmsg,
        ),
        eaprog_sec(
            "cgroup/recvmsg6",
            Type::CGroupSockAddr,
            Attach::CGroupUdp6Recvmsg,
        ),
        eaprog_sec("cgroup/sysctl", Type::CGroupSysctl, Attach::CGroupSysctl),
    ];
}
