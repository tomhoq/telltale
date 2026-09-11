use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use pcap_file::pcap::PcapReader;
use pcap_file::DataLink;
use pf_core::{Error, Observation, Result};

use crate::{decode, Source};

/// Offline replay of a capture file — the source to use in tests, since it makes
/// a run deterministic.
pub struct PcapFileSource {
    path: PathBuf,
    reader: PcapReader<BufReader<File>>,
    datalink: DataLink,
}

impl PcapFileSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(Error::Capture(format!("no such file: {}", path.display())));
        }

        let file = File::open(&path)
            .map_err(|e| Error::Capture(format!("failed to open `{}`: {e}", path.display())))?;
        let reader = BufReader::new(file);
        let pcap_reader = PcapReader::new(reader)
            .map_err(|e| Error::Capture(format!("failed to parse pcap header in `{}`: {e}", path.display())))?;
        let datalink = pcap_reader.header().datalink;

        Ok(Self {
            path,
            reader: pcap_reader,
            datalink,
        })
    }
}

impl Source for PcapFileSource {
    fn describe(&self) -> String {
        format!("pcap:{}", self.path.display())
    }

    fn next_observation(&mut self) -> Result<Option<Observation>> {
        while let Some(packet_result) = self.reader.next_packet() {
            let packet = packet_result.map_err(|e| {
                Error::Capture(format!(
                    "error reading packet from `{}`: {e}",
                    self.path.display()
                ))
            })?;

            // Replay must use the packet's own timestamp rather than wall clock,
            // otherwise the session assembler's inactivity timeout will expire
            // everything at once.
            let at = SystemTime::UNIX_EPOCH + packet.timestamp;

            let observation = match self.datalink {
                DataLink::ETHERNET => decode::ethernet_frame(&packet.data, at),
                DataLink::IPV4 | DataLink::IPV6 | DataLink::RAW => {
                    decode::ip_packet(&packet.data, at)
                }
                DataLink::LINUX_SLL => {
                    // Linux cooked-mode capture v1 header is 16 bytes, followed by IP
                    if packet.data.len() > 16 {
                        decode::ip_packet(&packet.data[16..], at)
                    } else {
                        None
                    }
                }
                DataLink::LINUX_SLL2 => {
                    // Linux cooked-mode capture v2 header is 20 bytes, followed by IP
                    if packet.data.len() > 20 {
                        decode::ip_packet(&packet.data[20..], at)
                    } else {
                        None
                    }
                }
                _ => {
                    // Fall back to attempting ethernet frame, then bare IP packet
                    decode::ethernet_frame(&packet.data, at)
                        .or_else(|| decode::ip_packet(&packet.data, at))
                }
            };

            if let Some(obs) = observation {
                return Ok(Some(obs));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use pcap_file::pcap::{PcapPacket, PcapWriter};
    use pf_core::{TcpHeader, Transport};

    fn make_ethernet_ip_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = vec![0xff; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        let tcp_seg = {
            let mut s = Vec::new();
            s.extend_from_slice(&src_port.to_be_bytes());
            s.extend_from_slice(&dst_port.to_be_bytes());
            s.extend_from_slice(&[0; 8]); // seq + ack
            s.extend_from_slice(&[0x50, 0x02]); // 5 words, SYN flag
            s.extend_from_slice(&[0; 6]);
            s
        };
        let ip_pkt = {
            let mut p = vec![0x45, 0x00];
            p.extend_from_slice(&((20 + tcp_seg.len()) as u16).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
            p.extend_from_slice(&[192, 168, 1, 100]); // src IP
            p.extend_from_slice(&[192, 168, 1, 1]);   // dst IP
            p.extend_from_slice(&tcp_seg);
            p
        };
        frame.extend_from_slice(&ip_pkt);
        frame
    }

    #[test]
    fn replays_pcap_packets() {
        let temp_dir = std::env::temp_dir();
        let pcap_path = temp_dir.join(format!("test_replay_{}.pcap", std::process::id()));

        // Create a PCAP file using PcapWriter
        let file = File::create(&pcap_path).unwrap();
        let mut pcap_writer = PcapWriter::new(file).unwrap();

        let frame1 = make_ethernet_ip_tcp(45678, 80);
        let frame2 = make_ethernet_ip_tcp(45678, 443);

        pcap_writer
            .write_packet(&PcapPacket::new(
                Duration::from_secs(100),
                frame1.len() as u32,
                &frame1,
            ))
            .unwrap();
        pcap_writer
            .write_packet(&PcapPacket::new(
                Duration::from_secs(102),
                frame2.len() as u32,
                &frame2,
            ))
            .unwrap();
        drop(pcap_writer);

        let mut source = PcapFileSource::open(&pcap_path).unwrap();
        assert_eq!(source.describe(), format!("pcap:{}", pcap_path.display()));

        let obs1 = source.next_observation().unwrap().expect("expected packet 1");
        assert_eq!(obs1.at, SystemTime::UNIX_EPOCH + Duration::from_secs(100));
        assert_eq!(obs1.source.port, 45678);
        assert_eq!(obs1.destination.port, 80);
        assert_eq!(obs1.transport, Transport::Tcp);
        assert_eq!(obs1.tcp.as_ref().map(|t| t.flags), Some(TcpHeader::SYN));

        let obs2 = source.next_observation().unwrap().expect("expected packet 2");
        assert_eq!(obs2.at, SystemTime::UNIX_EPOCH + Duration::from_secs(102));
        assert_eq!(obs2.source.port, 45678);
        assert_eq!(obs2.destination.port, 443);

        assert!(source.next_observation().unwrap().is_none());

        let _ = std::fs::remove_file(&pcap_path);
    }
}
