// TODO:
// [ ] Add full nested packet parsing and preparation for Lua scripts
// [x] Add HEP3 wrapping
// [x] Add PACKET_FANOUT support
//

pub mod dummy;
pub mod rtcp;
pub mod rtp;

use self::dummy::DummyPacket;
use errors::*;
use futures::future::Future;
use hep3::*;
use lua::Scripting;
use objpool;
use pnet::datalink::{
    self, Channel, Channel::Ethernet, Config, DataLinkReceiver, FanoutOption, FanoutType,
    NetworkInterface,
};
use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    icmpv6::Icmpv6Packet,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet, PacketSize,
};
use pnet::util::MacAddr;
use std::{
    cell::RefCell,
    fmt::Display,
    net::IpAddr,
    path::Path,
    sync::{mpsc::Sender, Arc},
    thread,
};
use time;

//=======================================================================================
// Packet dissector

pub struct Dissector {
    name: String,
    interface: Option<NetworkInterface>,
    rx: Box<DataLinkReceiver>,
    tx: Sender<objpool::Item<Vec<u8>>>,
    plan: RefCell<Scripting>,
}

impl Dissector {
    fn matching_interface(name: &str) -> Option<NetworkInterface> {
        let interface_names_match = |iface: &NetworkInterface| iface.name == name;

        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();

        debug!("Available interfaces:");
        for iface in &interfaces {
            debug!("{}", iface);
        }

        interfaces.into_iter().filter(interface_names_match).next()
    }

    pub fn datalink_from_interface(name: &str) -> Result<Box<DataLinkReceiver>, Error> {
        let interface = Dissector::matching_interface(name)
            .expect(&format!("No matching interface '{}' found", name));

        let mut config: Config = Default::default();
        config.linux_fanout = Some(FanoutOption {
            group_id: 2601, // Arbitrary @todo Allow specifying group id
            fanout_type: FanoutType::HASH,
            defrag: true,
            rollover: false,
        });

        // Create a new channel, dealing with layer 2 packets
        let (_, rx) = match datalink::channel(&interface, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };
        Ok(rx)
    }

    pub fn datalink_from_file<P: AsRef<Path> + Display>(
        path: P,
    ) -> Result<Box<DataLinkReceiver>, Error> {
        debug!("Opening pcap file {}", path);
        // Create a new channel, dealing with layer 2 packets
        let (_, rx) = match datalink::pcap::from_file(path, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };
        Ok(rx)
    }

    pub fn new(
        name: &str,
        rx: Box<DataLinkReceiver>,
        tx: Sender<objpool::Item<Vec<u8>>>,
    ) -> Result<Self, Error> {
        Ok(Dissector {
            name: name.to_owned(),
            interface: Dissector::matching_interface(name),
            rx,
            tx,
            plan: RefCell::new(Scripting::new()), // @fixme perhaps just use &mut self
        })
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let pool = objpool::Pool::with_capacity(100, || vec![0; 1600]);
        loop {
            match self.rx.next() {
                Ok(packet) => {
                    info!("Received packet on thread {:?}", thread::current().name());

                    let mut hepbuf = pool.get();
                    let mut hep = MutableHepPacket::new(&mut hepbuf).unwrap();
                    let mut hep_builder = HepBuilder::new(&mut hep);

                    if cfg!(target_os = "macos") {
                        if let Some(ref intf) = self.interface {
                            if intf.is_up()
                                && !intf.is_broadcast()
                                && !intf.is_loopback()
                                && intf.is_point_to_point()
                            {
                                let mut buf = pool.get();
                                let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf)
                                    .expect("Cannot create fake ethernet frame");

                                // Maybe is TUN interface
                                let version = Ipv4Packet::new(&packet).unwrap().get_version();
                                if version == 4 {
                                    fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                                    fake_ethernet_frame.set_payload(&packet);
                                    handle_ethernet_frame(
                                        &self.interface,
                                        &fake_ethernet_frame.to_immutable(),
                                        &mut hep_builder,
                                        &self.plan,
                                    );
                                    // if ok then
                                    self.tx.send(hepbuf);
                                    continue;
                                } else if version == 6 {
                                    fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                    fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                                    fake_ethernet_frame.set_payload(&packet);
                                    handle_ethernet_frame(
                                        &self.interface,
                                        &fake_ethernet_frame.to_immutable(),
                                        &mut hep_builder,
                                        &self.plan,
                                    );
                                    // if ok then
                                    self.tx.send(hepbuf);
                                    continue;
                                }
                            }
                        }
                    }

                    let eth_packet =
                        EthernetPacket::new(packet).expect("Failed to parse ethernet packet");
                    handle_ethernet_frame(
                        &self.interface,
                        &eth_packet,
                        &mut hep_builder,
                        &self.plan,
                    );
                    // if ok then
                    // self.tx.send(hepbuf); // this must be handled by plan callbacks...somehow
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    return Err(format_err!("An error occurred while reading: {}", e));
                }
            }
        }
        // Ok(())
    }
}

fn handle_ethernet_frame(
    interface: &Option<NetworkInterface>,
    ethernet: &EthernetPacket,
    hep: &mut HepBuilder,
    plan: &RefCell<Scripting>,
) {
    let interface_name = if let Some(intf) = interface {
        &intf.name[..]
    } else {
        "file"
    };
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet, hep, plan),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet, hep, plan),
        _ => trace!(
            "[{}]: Ignoring packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

fn handle_ipv4_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    hep: &mut HepBuilder,
    plan: &RefCell<Scripting>,
) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        hep.add_chunk(Chunk::ipProtocolFamily(IpProtocolFamilies::IPv4))
            .add_chunk(Chunk::ipv4SourceAddress(header.get_source().octets()))
            .add_chunk(Chunk::ipv4TargetAddress(header.get_destination().octets()));

        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            hep,
            plan,
        );
    } else {
        info!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    hep: &mut HepBuilder,
    plan: &RefCell<Scripting>,
) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        hep.add_chunk(Chunk::ipProtocolFamily(IpProtocolFamilies::IPv6))
            .add_chunk(Chunk::ipv6SourceAddress(header.get_source().octets()))
            .add_chunk(Chunk::ipv6TargetAddress(header.get_destination().octets()));

        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            hep,
            plan,
        );
    } else {
        info!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    hep: &mut HepBuilder,
    plan: &RefCell<Scripting>,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, hep, plan)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet, hep, plan)
        }
        _ => trace!(
            "[{}]: Ignoring {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    hep: &mut HepBuilder,
    plan: &RefCell<Scripting>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        hep.add_chunk(Chunk::ipProtocolId(IpProtocolIds::UDP))
            .add_chunk(Chunk::sourcePort(udp.get_source()))
            .add_chunk(Chunk::targetPort(udp.get_destination()));

        // hep.add_chunk();

        trace!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );

        handle_payload(interface_name, udp.payload(), hep, plan);
    } else {
        info!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    hep: &mut HepBuilder,
    plan: &RefCell<Scripting>,
) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        hep.add_chunk(Chunk::ipProtocolId(IpProtocolIds::TCP))
            .add_chunk(Chunk::sourcePort(tcp.get_source()))
            .add_chunk(Chunk::targetPort(tcp.get_destination()));

        trace!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );

        handle_payload(interface_name, tcp.payload(), hep, plan);
    } else {
        info!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_payload(
    _interface_name: &str,
    packet: &[u8],
    hep: &mut HepBuilder,
    plan: &RefCell<Scripting>,
) {
    // Run capture_plan over packet byte array

    // info!("Original packet size {}", packet.len());

    let packet = DummyPacket::new(packet).expect("Failed to parse packet");

    info!("Payload {:?}", packet.payload());

    // Capture plan may call other parse functions to try and parse it
    plan.borrow_mut().run(&packet); // this may call some callbacks to try parse the payload

    // send_hep(hep); // this will be called by the plan
}

fn send_hep(hep: &mut HepBuilder) {
    let tm = time::precise_time_ns();
    let tm_sec = tm / 1_000_000;
    let tm_ms = (tm - tm_sec * 1_000_000) / 1_000;

    hep
        .add_chunk(Chunk::timestampSec(tm_sec as u32))
        .add_chunk(Chunk::timestampMicrosecOffset(tm_ms as u32))
        .add_chunk(Chunk::protocolType(SubProtocols::SIP))
        .add_chunk(Chunk::captureAgentId(0x2001))
        .add_chunk(Chunk::authKey("myHep".to_string().into_bytes()))
        .add_chunk(Chunk::packetPayload(// @todo not present in one hep package
            "INVITE blablabla".to_string().into_bytes(),
        ))
        // @todo additional - see allowed types
        // .add_chunk(Chunk::correlationId("somecorrid".to_string().into_bytes()))
        // .add_chunk(Chunk::mosValue(0x200))
        .build();
}
