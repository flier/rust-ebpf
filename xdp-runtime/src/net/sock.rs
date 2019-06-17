#![allow(non_upper_case_globals)]

/*
 * Address families.
 */

/// unspecified
pub const AF_UNSPEC: u8 = 0;
/// local to host (pipes)
pub const AF_UNIX: u8 = 1;
/// backward compatibility
pub const AF_LOCAL: u8 = AF_UNIX;
/// internetwork: UDP, TCP, etc.
pub const AF_INET: u8 = 2;
/// arpanet imp addresses
pub const AF_IMPLINK: u8 = 3;
/// pup protocols: e.g. BSP
pub const AF_PUP: u8 = 4;
/// mit CHAOS protocols
pub const AF_CHAOS: u8 = 5;
/// XEROX NS protocols
pub const AF_NS: u8 = 6;
/// ISO protocols
pub const AF_ISO: u8 = 7;
pub const AF_OSI: u8 = AF_ISO;
/// European computer manufacturers
pub const AF_ECMA: u8 = 8;
/// datakit protocols
pub const AF_DATAKIT: u8 = 9;
/// CCITT protocols, X.25 etc
pub const AF_CCITT: u8 = 10;
/// IBM SNA
pub const AF_SNA: u8 = 11;
/// DECnet
pub const AF_DECnet: u8 = 12;
/// DEC Direct data link interface
pub const AF_DLI: u8 = 13;
/// LAT
pub const AF_LAT: u8 = 14;
/// NSC Hyperchannel
pub const AF_HYLINK: u8 = 15;
/// Apple Talk
pub const AF_APPLETALK: u8 = 16;
/// Internal Routing Protocol
pub const AF_ROUTE: u8 = 17;
/// Link layer interface
pub const AF_LINK: u8 = 18;
/// eXpress Transfer Protocol (no AF)
pub const pseudo_AF_XTP: u8 = 19;
/// connection-oriented IP, aka ST II
pub const AF_COIP: u8 = 20;
/// Computer Network Technology
pub const AF_CNT: u8 = 21;
/// Help Identify RTIP packets
pub const pseudo_AF_RTIP: u8 = 22;
/// Novell Internet Protocol
pub const AF_IPX: u8 = 23;
/// Simple Internet Protocol
pub const AF_SIP: u8 = 24;
/// Help Identify PIP packets
pub const pseudo_AF_PIP: u8 = 25;
/// Network Driver 'raw' access
pub const AF_NDRV: u8 = 27;
/// Integrated Services Digital Network
pub const AF_ISDN: u8 = 28;
/// CCITT E.164 recommendation
pub const AF_E164: u8 = AF_ISDN;
/// Internal key-management function
pub const pseudo_AF_KEY: u8 = 29;
/// IPv6
pub const AF_INET6: u8 = 30;
/// native ATM access
pub const AF_NATM: u8 = 31;
/// Kernel event messages
pub const AF_SYSTEM: u8 = 32;
/// NetBIOS
pub const AF_NETBIOS: u8 = 33;
/// PPP communication protocol
pub const AF_PPP: u8 = 34;
/// Used by BPF to not rewrite headers in interface output routine
pub const pseudo_AF_HDRCMPLT: u8 = 35;
/// Reserved for internal usage
pub const AF_RESERVED_36: u8 = 36;
/// IEEE 802.11 protocol
pub const AF_IEEE80211: u8 = 37;
pub const AF_UTUN: u8 = 38;
pub const AF_MAX: u8 = 40;
