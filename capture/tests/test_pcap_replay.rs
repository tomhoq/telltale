use std::fs::File;
use std::time::{Duration, SystemTime};

use pcap_file::pcap::{PcapPacket, PcapWriter};
use pf_capture::sources::PcapFileSource;
use pf_capture::Source;
use pf_core::{TcpHeader, Transport};

fn make_tcp_syn_frame(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut frame = vec![0xff; 12];
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let tcp_seg = {
        let mut s = Vec::new();
        s.extend_from_slice(&src_port.to_be_bytes());
        s.extend_from_slice(&dst_port.to_be_bytes());
        s.extend_from_slice(&1u32.to_be_bytes()); // seq
        s.extend_from_slice(&0u32.to_be_bytes()); // ack
        s.extend_from_slice(&[0x50, 0x02]); // 5 words, SYN
        s.extend_from_slice(&[0x72, 0x10]); // window 29200
        s.extend_from_slice(&[0, 0, 0, 0]); // checksum + urgent
        s
    };

    let ip_pkt = {
        let mut p = vec![0x45, 0x00];
        p.extend_from_slice(&((20 + tcp_seg.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, 6, 0, 0]);
        p.extend_from_slice(&src_ip);
        p.extend_from_slice(&dst_ip);
        p.extend_from_slice(&tcp_seg);
        p
    };

    frame.extend_from_slice(&ip_pkt);
    frame
}

#[test]
fn test_pcap_replay_full_flow() {
    let temp_dir = std::env::temp_dir();
    let pcap_path = temp_dir.join(format!("test_replay_fixture_{}.pcap", std::process::id()));

    let file = File::create(&pcap_path).expect("failed to create temp pcap");
    let mut writer = PcapWriter::new(file).expect("failed to init pcap writer");

    let src = [198, 51, 100, 42];
    let dst = [192, 168, 1, 10];
    let ports = [80, 443, 22, 8080];

    for (i, &port) in ports.iter().enumerate() {
        let frame = make_tcp_syn_frame(src, dst, 54321 + i as u16, port);
        let timestamp = Duration::from_secs(1700000000 + (i as u64 * 5));
        writer
            .write_packet(&PcapPacket::new(timestamp, frame.len() as u32, &frame))
            .expect("failed to write packet");
    }
    drop(writer);

    let mut source = PcapFileSource::open(&pcap_path).expect("failed to open pcap source");

    let mut observed_ports = Vec::new();
    let mut timestamps = Vec::new();
    while let Some(obs) = source.next_observation().expect("failed next observation") {
        assert_eq!(obs.source.addr.to_string(), "198.51.100.42");
        assert_eq!(obs.destination.addr.to_string(), "192.168.1.10");
        assert_eq!(obs.transport, Transport::Tcp);
        assert_eq!(obs.tcp.as_ref().map(|t| t.flags), Some(TcpHeader::SYN));
        observed_ports.push(obs.destination.port);
        timestamps.push(obs.at);
    }

    assert_eq!(observed_ports, vec![80, 443, 22, 8080]);
    assert_eq!(timestamps[0], SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000));
    assert_eq!(timestamps[3], SystemTime::UNIX_EPOCH + Duration::from_secs(1700000015));

    let _ = std::fs::remove_file(pcap_path);
}

#[test]
fn test_fixture_generation_and_replay() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_dir = manifest_dir.join("tests").join("fixtures");
    std::fs::create_dir_all(&fixture_dir).expect("failed to create fixtures dir");
    let fixture_path = fixture_dir.join("sample_syn_scan.pcap");

    let file = File::create(&fixture_path).expect("failed to create fixture file");
    let mut writer = PcapWriter::new(file).expect("failed to init pcap writer");

    let src = [198, 51, 100, 42];
    let dst = [192, 168, 1, 10];
    let ports = [22, 80, 443, 3389, 8080];

    for (i, &port) in ports.iter().enumerate() {
        let frame = make_tcp_syn_frame(src, dst, 54000 + i as u16, port);
        let timestamp = Duration::from_secs(1700000000 + (i as u64 * 2));
        writer
            .write_packet(&PcapPacket::new(timestamp, frame.len() as u32, &frame))
            .expect("failed to write packet");
    }
    drop(writer);

    let mut source = PcapFileSource::open(&fixture_path).expect("failed to open fixture pcap");
    let mut count = 0;
    while let Some(obs) = source.next_observation().expect("failed next obs") {
        assert_eq!(obs.source.addr.to_string(), "198.51.100.42");
        assert_eq!(obs.destination.port, ports[count]);
        count += 1;
    }
    assert_eq!(count, 5);
}

