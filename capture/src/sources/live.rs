use std::fmt;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use pf_core::{Error, Observation, Result};
use pnet::datalink::{self, Channel, Config, DataLinkReceiver, NetworkInterface};

use crate::{decode, Source};

/// How long a read waits before coming back empty-handed. It exists so the read
/// loop is not wedged inside a syscall forever — a quiet interface still ticks
/// through the loop and can notice a hard error on the socket.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Live capture from a network interface.
///
/// Opening one needs `CAP_NET_RAW` (`setcap cap_net_raw,cap_net_admin+eip` on
/// the binary, or root). On Windows it needs Npcap instead, checked on open —
/// see [`crate::npcap`] — and interface names are Npcap device paths
/// (`\Device\NPF_{GUID}`); [`interfaces`] lists them with readable
/// descriptions. Timestamps come from the clock at the moment the frame
/// is read, not from the kernel's own hardware/software timestamp, so they run
/// a little late under load; that is fine for idle timeouts and wrong for
/// anything measuring inter-packet timing, which is why the pcap replay path
/// must use the file's own timestamps instead.
pub struct LiveSource {
    interface: String,
    /// in the future: BPF filter can b applied at the kernel, so uninteresting traffic never reaches
    /// user space.
    filter: Option<String>,
    /// The interface's own addresses, read once at open.
    addresses: Vec<IpAddr>,
    /// Frames sent from any of these are dropped before they reach the
    /// pipeline. Empty unless [`LiveSource::incoming_only`] was asked for.
    drop_sources: Vec<IpAddr>,
    /// How the interface frames what it delivers. Ethernet everywhere except
    /// point-to-point links (tun, ppp), which hand over bare IP packets.
    link: Link,
    receiver: Box<dyn DataLinkReceiver>,
}

#[derive(Debug, Clone, Copy)]
enum Link {
    Ethernet,
    RawIp,
}

impl LiveSource {
    // Into<String> accepts flexible argument types, e.g. &str, String, etc.
    pub fn open(interface: impl Into<String>, filter: Option<String>) -> Result<Self> {
        let interface = interface.into();

        // Accepting a filter we cannot enforce would silently capture the
        // traffic the caller asked us to leave alone, so refuse instead. See
        // the field comment: this lifts once the filter is compiled and pushed
        // into the kernel.
        if let Some(filter) = &filter {
            return Err(Error::Capture(format!(
                "filter `{filter}` cannot be applied yet; refusing rather than capturing unfiltered"
            )));
        }

        let device = find_interface(&interface)?;
        let link = if device.is_point_to_point() {
            Link::RawIp // for packets where there is no L2 (TAP or TUN), start parsing at the IP header
        } else {
            Link::Ethernet // for packets where there is an L2 (Ethernet, Wi-Fi, etc.), start parsing at the Ethernet header
        };

        let config = Config {
            read_timeout: Some(READ_TIMEOUT),
            // A sensor watching a mirror port sees nothing without this. On an
            // interface that cannot do it the channel simply fails to open,
            // which is a clearer failure than capturing a third of the traffic.
            promiscuous: true,
            ..Default::default()
        };

        let receiver = match datalink::channel(&device, config) {
            Ok(Channel::Ethernet(_, receiver)) => receiver,
            Ok(_) => {
                return Err(Error::Capture(format!(
                    "`{interface}` returned a channel type this build does not handle"
                )))
            }
            Err(source) => return Err(open_failed(&interface, source)),
        };

        Ok(Self {
            addresses: device.ips.iter().map(|network| network.ip()).collect(),
            drop_sources: Vec::new(),
            interface,
            filter,
            link,
            receiver,
        })
    }

    /// Keep only traffic arriving at this host: drop every frame whose source
    /// is one of the interface's own addresses. Without it, connections the
    /// host opens itself make it the session initiator, and its own stack gets
    /// fingerprinted as if it were the intruder.
    ///
    /// Fails on an interface with no addresses, where there is nothing to
    /// filter by — capturing unfiltered instead would be the same silent
    /// surprise [`LiveSource::open`] refuses for a BPF filter. On Windows pnet
    /// only reports IPv4 addresses, so IPv6 traffic from this host still gets
    /// through there.
    pub fn incoming_only(mut self) -> Result<Self> {
        if self.addresses.is_empty() {
            return Err(Error::Capture(format!(
                "`{}` has no IP address to tell incoming traffic apart by; \
                 pick another interface or pass --both-directions",
                self.interface
            )));
        }
        self.drop_sources = self.addresses.clone();
        Ok(self)
    }

    /// The addresses whose frames are being dropped; empty when both
    /// directions are captured.
    pub fn dropped_sources(&self) -> &[IpAddr] {
        &self.drop_sources
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref() // as_deref() converts Option<String> to Option<&str>
    }
}

impl Source for LiveSource {
    fn describe(&self) -> String {
        format!("live:{}", self.interface)
    }

    fn next_observation(&mut self) -> Result<Option<Observation>> {
        loop {
            let frame = match self.receiver.next() {
                Ok(frame) => frame,
                // Nothing arrived within the read timeout, or a signal cut the
                // syscall short. An interface is never exhausted, so keep
                // waiting rather than reporting end of stream.
                Err(source) if is_retryable(&source) => continue,
                Err(source) => {
                    return Err(Error::Capture(format!(
                        "read from `{}` failed: {source}",
                        self.interface
                    )))
                }
            };

            // Timestamp at the read, before decoding, so a slow decode does not
            // show up as inter-packet delay.
            let at = SystemTime::now();

            // Undecodable and uninteresting frames — ARP, STP, a truncated
            // header — are the normal background of a live interface, so they
            // are skipped rather than returned as errors.
            let decoded = match self.link {
                Link::Ethernet => decode::ethernet_frame(frame, at),
                Link::RawIp => decode::ip_packet(frame, at),
            };

            if let Some(observation) = decoded {
                if self.drop_sources.contains(&observation.source.addr) {
                    continue;
                }
                return Ok(Some(observation));
            }
        }
    }
}

/// A capture interface, described for a person choosing one. Keeps pnet's own
/// type inside this crate.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// What [`LiveSource::open`] takes.
    pub name: String,
    /// The adapter's readable name. On Windows it is the only way to tell the
    /// `\Device\NPF_{GUID}` paths apart; elsewhere it is usually empty.
    pub description: String,
    /// Configured addresses, which is often how people recognise "the one on
    /// the LAN". IPv4 only on Windows, a pnet limitation.
    pub addresses: Vec<IpAddr>,
}

impl fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.description.as_str() {
            "" => f.write_str(&self.name),
            description => write!(f, "{} ({description})", self.name),
        }
    }
}

/// Every interface a [`LiveSource`] could open, in the order the OS reports
/// them.
pub fn interfaces() -> Result<Vec<InterfaceInfo>> {
    Ok(datalink_interfaces()?.into_iter().map(info).collect())
}

fn info(interface: NetworkInterface) -> InterfaceInfo {
    InterfaceInfo {
        addresses: interface.ips.iter().map(|network| network.ip()).collect(),
        name: interface.name,
        description: interface.description,
    }
}

/// The single gate in front of pnet's datalink layer. On Windows every
/// datalink call — listing included — goes through Npcap's Packet.dll, which
/// is delay-loaded: pnet crashes rather than errors if it is missing, so check
/// first.
fn datalink_interfaces() -> Result<Vec<NetworkInterface>> {
    #[cfg(windows)]
    crate::npcap::ensure_available()?;

    Ok(datalink::interfaces())
}

fn find_interface(name: &str) -> Result<NetworkInterface> {
    let interfaces = datalink_interfaces()?;

    if let Some(found) = interfaces.iter().find(|candidate| candidate.name == name) {
        return Ok(found.clone());
    }

    let available: Vec<String> = interfaces
        .into_iter()
        .map(|interface| info(interface).to_string())
        .collect();
    Err(Error::Capture(format!(
        "no interface `{name}`; this host has: {}",
        available.join(", ")
    )))
}

/// Point at the capability rather than the errno — a bare "permission denied"
/// out of a packet sniffer sends people to `sudo` when a capability is enough.
fn open_failed(interface: &str, source: io::Error) -> Error {
    if source.kind() == io::ErrorKind::PermissionDenied {
        #[cfg(windows)]
        let needs = "Npcap was installed with access restricted to Administrators; \
                     run from an elevated prompt, or reinstall Npcap without that option";
        #[cfg(not(windows))]
        let needs = "needs CAP_NET_RAW \
                     (`sudo setcap cap_net_raw,cap_net_admin+eip <binary>`) or root";
        return Error::Capture(format!("cannot capture on `{interface}`: {needs}"));
    }
    Error::Capture(format!("cannot capture on `{interface}`: {source}"))
}

fn is_retryable(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LiveSource` holds a channel and so is not `Debug`; unwrap the error by
    /// hand rather than derive `Debug` purely to satisfy `unwrap_err`.
    fn open_error(interface: &str, filter: Option<String>) -> Error {
        match LiveSource::open(interface, filter) {
            Err(error) => error,
            Ok(source) => panic!("expected `{}` to fail to open", source.describe()),
        }
    }

    #[test]
    fn a_filter_is_refused_rather_than_ignored() {
        let error = open_error("lo", Some("tcp port 22".into()));
        assert!(error.to_string().contains("refusing"), "{error}");
    }

    #[test]
    fn an_unknown_interface_lists_the_real_ones() {
        let error = open_error("definitely-not-an-interface", None);
        assert!(error.to_string().contains("no interface"), "{error}");
    }
}
