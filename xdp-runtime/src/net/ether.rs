#![allow(clippy::many_single_char_names)]

use core::fmt;

use ebpf_runtime::be16;

use crate::net::Readable;

pub const ETH_ALEN: usize = 6;

/// Ethernet Loopback packet
pub const ETH_P_LOOP: be16 = 0x0060;
/// Xerox PUP packet
pub const ETH_P_PUP: be16 = 0x0200;
/// Xerox PUP Addr Trans packet
pub const ETH_P_PUPAT: be16 = 0x0201;
/// TSN (IEEE 1722) packet
pub const ETH_P_TSN: be16 = 0x22F0;
/// ERSPAN version 2 (type III)
pub const ETH_P_ERSPAN2: be16 = 0x22EB;
/// Internet Protocol packet
pub const ETH_P_IP: be16 = 0x0800;
/// CCITT X.25
pub const ETH_P_X25: be16 = 0x0805;
/// Address Resolution packet
pub const ETH_P_ARP: be16 = 0x0806;
/// G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_BPQ: be16 = 0x08FF;
/// Xerox IEEE802.3 PUP packet
pub const ETH_P_IEEEPUP: be16 = 0x0a00;
/// Xerox IEEE802.3 PUP Addr Trans packet
pub const ETH_P_IEEEPUPAT: be16 = 0x0a01;
/// B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_BATMAN: be16 = 0x4305;
/// DEC Assigned proto
pub const ETH_P_DEC: be16 = 0x6000;
/// DEC DNA Dump/Load
pub const ETH_P_DNA_DL: be16 = 0x6001;
/// DEC DNA Remote Console
pub const ETH_P_DNA_RC: be16 = 0x6002;
/// DEC DNA Routing
pub const ETH_P_DNA_RT: be16 = 0x6003;
/// DEC LAT
pub const ETH_P_LAT: be16 = 0x6004;
/// DEC Diagnostics
pub const ETH_P_DIAG: be16 = 0x6005;
/// DEC Customer use
pub const ETH_P_CUST: be16 = 0x6006;
/// DEC Systems Comms Arch
pub const ETH_P_SCA: be16 = 0x6007;
/// Trans Ether Bridging
pub const ETH_P_TEB: be16 = 0x6558;
/// Reverse Addr Res packet
pub const ETH_P_RARP: be16 = 0x8035;
/// Appletalk DDP
pub const ETH_P_ATALK: be16 = 0x809B;
/// Appletalk AARP
pub const ETH_P_AARP: be16 = 0x80F3;
/// 802.1Q VLAN Extended Header
pub const ETH_P_8021Q: be16 = 0x8100;
/// ERSPAN type II
pub const ETH_P_ERSPAN: be16 = 0x88BE;
/// IPX over DIX
pub const ETH_P_IPX: be16 = 0x8137;
/// IPv6 over bluebook
pub const ETH_P_IPV6: be16 = 0x86DD;
/// IEEE Pause frames. See 802.3 31B
pub const ETH_P_PAUSE: be16 = 0x8808;
/// Slow Protocol. See 802.3ad 43B
pub const ETH_P_SLOW: be16 = 0x8809;
/// Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
pub const ETH_P_WCCP: be16 = 0x883E;
/// MPLS Unicast traffic
pub const ETH_P_MPLS_UC: be16 = 0x8847;
/// MPLS Multicast traffic
pub const ETH_P_MPLS_MC: be16 = 0x8848;
/// MultiProtocol Over ATM
pub const ETH_P_ATMMPOA: be16 = 0x884c;
/// PPPoE discovery messages
pub const ETH_P_PPP_DISC: be16 = 0x8863;
/// PPPoE session messages
pub const ETH_P_PPP_SES: be16 = 0x8864;
/// HPNA, wlan link local tunnel
pub const ETH_P_LINK_CTL: be16 = 0x886c;
/// Frame-based ATM Transport over Ethernet
pub const ETH_P_ATMFATE: be16 = 0x8884;
/// Port Access Entity (IEEE 802.1X)
pub const ETH_P_PAE: be16 = 0x888E;
/// ATA over Ethernet
pub const ETH_P_AOE: be16 = 0x88A2;
/// 802.1ad Service VLAN
pub const ETH_P_8021AD: be16 = 0x88A8;
/// 802.1 Local Experimental 1.
pub const ETH_P_802_EX1: be16 = 0x88B5;
/// 802.11 Preauthentication
pub const ETH_P_PREAUTH: be16 = 0x88C7;
/// TIPC
pub const ETH_P_TIPC: be16 = 0x88CA;
/// 802.1ae MACsec
pub const ETH_P_MACSEC: be16 = 0x88E5;
/// 802.1ah Backbone Service Tag
pub const ETH_P_8021AH: be16 = 0x88E7;
/// 802.1Q MVRP
pub const ETH_P_MVRP: be16 = 0x88F5;
/// IEEE 1588 Timesync
pub const ETH_P_1588: be16 = 0x88F7;
/// NCSI protocol
pub const ETH_P_NCSI: be16 = 0x88F8;
/// IEC 62439-3 PRP/HSRv0
pub const ETH_P_PRP: be16 = 0x88FB;
/// Fibre Channel over Ethernet
pub const ETH_P_FCOE: be16 = 0x8906;
/// Infiniband over Ethernet
pub const ETH_P_IBOE: be16 = 0x8915;
/// TDLS
pub const ETH_P_TDLS: be16 = 0x890D;
/// FCoE Initialization Protocol
pub const ETH_P_FIP: be16 = 0x8914;
/// IEEE 802.21 Media Independent Handover Protocol
pub const ETH_P_80221: be16 = 0x8917;
/// IEC 62439-3 HSRv1
pub const ETH_P_HSR: be16 = 0x892F;
/// Network Service Header
pub const ETH_P_NSH: be16 = 0x894F;
/// Ethernet loopback packet, per IEEE 802.3
pub const ETH_P_LOOPBACK: be16 = 0x9000;
/// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_QINQ1: be16 = 0x9100;
/// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_QINQ2: be16 = 0x9200;
/// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_QINQ3: be16 = 0x9300;
/// Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_EDSA: be16 = 0xDADA;
/// Fake VLAN Header for DSA [ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_DSA_8021Q: be16 = 0xDADB;
/// ForCES inter-FE LFB type
pub const ETH_P_IFE: be16 = 0xED3E;
/// IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]
pub const ETH_P_AF_IUCV: be16 = 0xFBFB;
/// If the value in the ethernet type is less than this value then the frame is Ethernet II. Else it is 802.3
pub const ETH_P_802_3_MIN: be16 = 0x0600;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Header {
    /// destination eth addr
    pub dest: MacAddr,
    /// source ether addr
    pub source: MacAddr,
    /// packet type ID field
    pub proto: be16,
}

impl Readable for Header {}

impl Header {
    #[inline]
    pub fn proto(&self) -> u16 {
        u16::from_be(self.proto)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MacAddr([u8; ETH_ALEN]);

impl From<[u8; ETH_ALEN]> for MacAddr {
    #[inline]
    fn from(octets: [u8; ETH_ALEN]) -> Self {
        MacAddr(octets)
    }
}

impl From<MacAddr> for [u8; ETH_ALEN] {
    #[inline]
    fn from(addr: MacAddr) -> [u8; ETH_ALEN] {
        addr.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let &[a, b, c, d, e, f] = &self.0;

        write!(
            fmt,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            a, b, c, d, e, f
        )
    }
}
