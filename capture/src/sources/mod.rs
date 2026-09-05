//! Concrete origins. Adding one means implementing [`crate::Source`] here and
//! adding a variant to the CLI — nothing else in the workspace changes.

pub mod honeypot_log;
pub mod live;
pub mod pcap_file;
pub mod tcpdump;

pub use honeypot_log::HoneypotLogSource;
pub use live::LiveSource;
pub use pcap_file::PcapFileSource;
pub use tcpdump::TcpdumpSource;
