// TODO:
// [ ] Send HEP3 queue to homer server
// [ ] Handle send errors more gracefully
// [ ] Track shutdown signal, flush queue and exit thread
// [ ] Use random local binding port instead of 9070
//
use errors::*;
use hep3::*;
use objpool;
use pnet::{
    packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, Packet, PacketSize},
    transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4},
};
use std::convert;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::Receiver;

pub struct Publisher {
    server: SocketAddr,
    state: State,
}

enum State {
    Preinit,
    Connected(UdpSocket),
}

const DEFAULT_PORT: u16 = 9060;

impl Publisher {
    pub fn new_homer<T: ToSocketAddrs>(server: T) -> Self {
        let addr = match server
            .to_socket_addrs()
            .expect("Invalid homer server address")
            .next()
        {
            Some(srv) => srv,
            None => unreachable!(), // @todo Error handling
        };
        Publisher {
            server: addr,
            state: State::Preinit,
        }
    }

    pub fn run(&mut self, rx: &Receiver<objpool::Item<Vec<u8>>>) -> Result<(), Error> {
        let sock = UdpSocket::bind("127.0.0.1:9070").expect("Couldn't bind to address");
        sock.connect(self.server)
            .expect("Couldn't connect to server");
        self.state = State::Connected(sock);

        loop {
            match rx.recv() {
                Ok(buf) => {
                    // Send packet to homer
                    match self.state {
                        State::Connected(ref sock) => {
                            let packet = HepPacket::new(&buf).unwrap();
                            trace!("SEND PACKET TO HOMER: {:#?}", packet);
                            let payload = &packet.packet()[..packet.packet_size()];
                            trace!("PAYLOAD: {:?}\n====================\n", payload);
                            sock.send(payload);
                        }
                        _ => unreachable!(),
                    }
                }
                Err(recvError) => {
                    error!("Failure {}", recvError);
                    // return Err("fail");
                } // @todo Handle exit
            }
        }
    }
}
