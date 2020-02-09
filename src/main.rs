// TODO:
// [ ] Use async logger in fern

// smoltcp

#![allow(dead_code)] // @todo remove; just reducing noise during development
#![allow(unused_must_use)] // @todo remove; just reducing noise during development
#![allow(unused_attributes)] // @todo remove; just reducing noise during development
#![allow(unused_imports)] // @todo remove; just reducing noise during development
//#![feature(link_args)]
//#![feature(nll)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![recursion_limit = "1024"]

// The reason this is needed is explained here: http://luajit.org/install.html#embed
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
#[cfg(feature="static")]
#[link_args = "-pagezero_size 10000 -image_base 100000000"]
extern "system" {}

#[macro_use]
extern crate serde_derive;
extern crate futures;
extern crate hep3;
extern crate num_cpus;
extern crate objpool;
extern crate pnet;
extern crate pnet_macros_support;
extern crate time;
#[macro_use]
extern crate log;
extern crate chrono;
extern crate fern;
#[macro_use]
extern crate luajit;
extern crate parsip;
#[macro_use]
extern crate hepagent;

mod decoders;
mod lua;
mod packets;
mod publish;

use hep3::HepPacket;
use objpool::Item;
use packets::Dissector;
use publish::Publisher;

//=======================================================================================
// Cmdline options

extern crate docopt;
use docopt::Docopt;

const USAGE: &str = "
Usage: hepagent [options] (-i <intf> | -r <pcap>)
       hepagent --version
       hepagent --help

Options:
    -i <intf>, --interface <intf>    Listen on interface. [default: any]
    -r <pcap>, --read-file <pcap>    Read pcap file.
    --hep-server <server>            HEP UDP server address. [default: 127.0.0.1:9060]
";
//     -t <type>, --type <type>         Capture types. (pcap, af_packet) [default: pcap] @todo REMOVE
//     -w <pcap>, --write-file <pcap>   Write pcap file.
//     -a <mins>, --rotate <mins>       Pcap rotation time in minutes.
//     -z, --compress                   Enable pcap compression.
//     --loop <n>                       Loop count over ReadFile. Use 0 to loop forever.
//     --readdump                       Max out pcap reading speed. Doesn't use packet timestamps.
//     -s <snap>, --snaplen <snap>      Snap length. [default: 16384]
//     --pr <ports>                     Port range to capture SIP. [default: 5060-5090]
//     -b <buf>, --buffer-size <buf>    Interface buffer size. (MB) [default: 32]
//     -l <level>, --log-level <level>  Log level. (debug, info, warning, error) [default: warning]
//     -o, --one-at-a-time              Read one packet at a time.
//     -p <path>, --log-path <path>     Log file path. [default: ./]
//     -n <name>, --log-name <name>     Log file name. [default: hepagent.log]
//     -m <mode>, --mode <mode>         Capture mode. (SIP, SIPDNS, SIPLOG, SIPRTP, SIPRTCP) [default: SIPRTCP]
//     --dedup                          Deduplicate packets.
//     --filter-interesting             Filter interesting packets.
//     --discard-uninteresting          Discard not interesting packets.
//     --hep-proxy <proxy>              HEP TLS proxy address.
//     --hep-pass <pass>                HepNodePW [default: myhep]
//     --hep-id <id>                    HepNodeID [default: 2002]
//     --vlan                           vlan
//     --erspan                         erspan
// ";

#[derive(Debug, Deserialize)]
struct Args {
    flag_interface: String,
    flag_read_file: Option<String>,
    flag_hep_server: String,
    // flag_type: CapType,
    // flag_write_file: Option<String>,
    // flag_rotate: Option<u32>,
    // flag_compress: bool,
    // flag_loop: Option<u32>,
    // flag_readdump: bool,
    // flag_snaplen: u32,
    // flag_pr: String,
    // flag_buffer_size: u32,
    // flag_log_level: String,
    // flag_one_at_a_time: bool,
    // flag_log_path: String,
    // flag_log_name: String,
    // flag_mode: ModeName,
    // flag_dedup: bool,
    // flag_filter_interesting: bool,
    // flag_discard_uninteresting: bool,
    // flag_hep_proxy: Option<String>,
    // flag_hep_pass: String,
    // flag_hep_id: u32,
    // flag_vlan: bool,
    // flag_erspan: bool,
}

// #[allow(non_camel_case_types)]
// #[derive(Debug, Deserialize, PartialEq)]
// enum CapType {
//     pcap,
//     af_packet,
// }

// #[allow(non_camel_case_types)]
// #[derive(Debug, Deserialize, PartialEq)]
// enum ModeName {
//     SIP,
//     SIPDNS,
//     SIPLOG,
//     SIPRTP,
//     SIPRTCP,
// }

//=======================================================================================
// Error handling

#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;

mod errors;

use errors::*;

//=======================================================================================
// Logging

fn setup_logging() -> Result<(), fern::InitError> {
    let base_config = fern::Dispatch::new().format(|out, message, record| {
        out.finish(format_args!(
            "{}[{}][{}] {}",
            chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
            record.target(),
            record.level(),
            message
        ))
    });

    let stdout_config = fern::Dispatch::new()
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout());

    let file_config = fern::Dispatch::new().level(log::LevelFilter::Trace).chain(
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true) // start log file anew each run
            .open("debug.log")?,
    );

    base_config.chain(stdout_config).chain(file_config).apply()?;

    Ok(())
}

//=======================================================================================
// Entry point

use pnet::{datalink::Channel, packet::ethernet::EthernetPacket};
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

fn main() {
    let args: Args = Docopt::new(USAGE)
        .unwrap_or_else(|e| e.exit())
        .deserialize()
        .unwrap_or_else(|e| e.exit());

    setup_logging().expect("failed to initialize logging");

    // assert_eq!(args.flag_type, CapType::pcap);

    trace!("{:?}", args);

    let mut publisher = Publisher::new_homer(args.flag_hep_server);
    let (tx, rx): (
        Sender<objpool::Item<Vec<u8>>>,
        Receiver<objpool::Item<Vec<u8>>>,
    ) = channel();

    let publish_thread = thread::spawn(move || {
        publisher.run(&rx);
    });

    #[cfg(target_os = "linux")]
    let cpus = num_cpus::get();

    #[cfg(not(target_os = "linux"))]
    let cpus = 1;

    info!("Using {} processing thread(s)", cpus);

    // build datalink
    // from file or interface

    // Run multiple threads of sniffer + single publisher.

    for x in 1..=cpus {
        let name = if let Some(file) = args.flag_read_file.clone() {
            file
        } else {
            args.flag_interface.clone()
        };

        let datalink_rx = match if let Some(file) = args.flag_read_file.clone() {
            Dissector::datalink_from_file(&file)
        } else {
            Dissector::datalink_from_interface(&args.flag_interface)
        } {
            Ok(datalink_rx) => datalink_rx,
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        let tx = tx.clone();

        thread::Builder::new()
            .name(format!("pcap{}", x))
            .spawn(move || {
                if let Err(ref e) = Dissector::new(&name, datalink_rx, tx).unwrap().run() {
                    error!("error: {}", e);

                    for cause in e.causes() {
                        error!("caused by: {}", cause);

                        if let Some(backtrace) = cause.backtrace() {
                            error!("backtrace: {:?}", backtrace);
                        }
                    }

                    std::process::exit(1);
                }
            })
            .expect("Couldn't launch packet capture thread");
    }

    publish_thread.join().expect("Publisher thread failed");
}
