// TODO
// [ ] Generate and parse all HEP3 types
// [ ] Try to make zero-copy payload wrapping if possible
//     [ ] Allow scatter/gather sending of packet data without copying?
// [ ] Run fuzzer to make parsing rock-solid
//

/* HEPv3 types */

#![allow(dead_code)]
//#![feature(custom_attribute)]

extern crate pnet_macros_support;

mod packet;
pub use packet::hep::*;

// macro_rules! hep_chunk {
//     ($name:ident, $ty:ty, $code:expr) => {
//         #[packet]
//         pub struct $name {
//             header: HepChunk,
//             payload: $ty,
//         }
//         impl From<$ty> for $name {
//             fn from(x: $ty) -> Self {
//                 Self {
//                     header: HepChunkHeader::new(0, $code, 6 + mem::size_of::<$ty>()),
//                     payload: x,
//                 }
//             }
//         }
//         // impl Into<[u8]> for $name {
//         //     fn into(self) -> [u8] {
//         //         let mut bytes = [u8; N];
//         //         //  pull segments of the array into fields
//         //     }
//         // }
//     };
// }

// #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct ArpHardwareType(pub u16);

// impl ArpHardwareType {
//     /// Create a new ArpHardwareType
//     pub fn new(value: u16) -> Self {
//         ArpHardwareType(value)
//     }
// }

// impl PrimitiveValues for ArpHardwareType {
//     type T = (u16,);
//     fn to_primitive_values(&self) -> (u16,) {
//         (self.0,)
//     }
// }

// #[derive(PartialEq, Debug)]
// pub struct GenericPayload<T> {
//     header: HepChunkHeader,
//     payload: T,
// }

// impl<T> From<T> for GenericPayload<T> {
//     fn from(x: T, code: u16) -> Self {
//         Self {
//             header: HepChunkHeader::new(0, code, 6 + mem::size_of::<T>()),
//             payload: x,
//         }
//     }
// }

// impl HepPacket {
//     pub fn empty() -> Self {
//         HepPacket {
//             header: HepHeader {
//                 hep_id: HEP_ID,
//                 total_length: 53,
//             },
//             ip_family: IpProtocolFamily::from(Family::IPv4),
//             ip_proto: IpProtocolId::from(Protocol::TCP),
//             src_port: SourcePort::from(2510),
//             dst_port: TargetPort::from(9066),
//             time_sec: TimestampSec::from(0),
//             time_usec: TimestampMicrosecOffset::from(0),
//             proto: ProtocolType::from(SubProtocol::Reserved),
//             capt_id: CaptureAgentId::from(228),
//         }
//     }
// }
// struct hep_chunk_str {
//        hep_chunk_t chunk;
//        char *data;
// } __attribute__((packed));

// struct hep_chunk_payload {
//     hep_chunk_t chunk;
//     char *data;
// } __attribute__((packed));

// /* Ethernet / IP / UDP header IPv4 */
// const int udp_payload_offset = 14+20+8;

// struct hep_hdr{
//     u_int8_t hp_v;            /* version */
//     u_int8_t hp_l;            /* length */
//     u_int8_t hp_f;            /* family */
//     u_int8_t hp_p;            /* protocol */
//     u_int16_t hp_sport;       /* source port */
//     u_int16_t hp_dport;       /* destination port */
// };

// struct hep_timehdr{
//     u_int32_t tv_sec;         /* seconds */
//     u_int32_t tv_usec;        /* useconds */
//     u_int16_t captid;         /* Capture ID node */
// };

// struct hep_iphdr{
//         struct in_addr hp_src;
//         struct in_addr hp_dst;      /* source and dest address */
// };

// struct hep_ip6hdr {
//         struct in6_addr hp6_src;        /* source address */
//         struct in6_addr hp6_dst;        /* destination address */
// };

#[cfg(test)]
mod tests {
    // use super::*;
    // use bincode::{config, deserialize, serialize};
    // #[test]
    // fn construct_u8_hepchunk() {
    //     let ch = HepChunkHeader::from(111u8);
    //     assert_eq!(ch.vendor_id, 0);
    //     assert_eq!(ch.type_id, 111);
    //     assert_eq!(ch.length, 111);
    // }

    // #[test]
    // fn construct_IpProtocolFamily() {
    //     let ip = IpProtocolFamily::from(111);
    //     assert_eq!(ch.vendor_id, 0);
    //     assert_eq!(ch.type_id, 111);
    //     assert_eq!(ch.length, 111);
    // }

    #[test]
    fn serialize_hep_chunk_packet() {
        use packet::hep::*;
        let mut ethernet_buffer = [0u8; 7];
        {
            let mut chunk = MutableHepChunkPacket::new(&mut ethernet_buffer).unwrap();

            chunk.set_vendor_id(0x0000);
            chunk.set_type_id(HepChunkTypeIds::IpProtocolFamily);
            chunk.set_length(7);
            chunk.set_payload(&vec![IpProtocolFamilies::IPv4]);
        }

        assert_eq!(&ethernet_buffer[..], b"\x00\x00\x00\x01\x00\x07\x02");
    }

    #[test]
    fn serialize_hep_packet() {
        use packet::hep::*;
        let mut ethernet_buffer = [0u8; 13];
        {
            let mut hep = MutableHepPacket::new(&mut ethernet_buffer).unwrap();

            hep.set_hep_id(HEP_ID);
            hep.set_total_length(13);
            hep.set_chunks(&[HepChunk {
                vendor_id: 0x0000,
                type_id: HepChunkTypeIds::IpProtocolFamily,
                length: 7,
                payload: vec![IpProtocolFamilies::IPv4],
            }]);
        }

        assert_eq!(
            &ethernet_buffer[..],
            b"\x48\x45\x50\x33\x00\x0d\x00\x00\x00\x01\x00\x07\x02"
        );
    }
    // let mut hep_packet = MutableHepPacket::new(&mut ethernet_buffer).unwrap();

    // hep_packet.set_hep_id(HEP_ID);

    // let ch = IpProtocolFamily::from(Family::IPv4);
    // let mut h = MutableHepPacket::from(Hep {});
    // h.populate(Hep {
    //     header: HepHeader {
    //         hep_id: HEP_ID,
    //         total_length: 53,
    //     },
    //     ip_family: IpProtocolFamily::from(Family::IPv4),
    //     ip_proto: IpProtocolId::from(Protocol::TCP),
    //     src_port: SourcePort::from(2510),
    //     dst_port: TargetPort::from(9066),
    //     time_sec: TimestampSec::from(0),
    //     time_usec: TimestampMicrosecOffset::from(0),
    //     proto: ProtocolType::from(SubProtocol::Reserved),
    //     capt_id: CaptureAgentId::from(228),
    // });
    // let encoded: Vec<u8> = config().big_endian().serialize(&ch).unwrap();
    // assert_eq!(encoded, b"\x00\x00\x00\x01\x00\x07\x02");
}
