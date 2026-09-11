use std::io;
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
/// the binary, or root). Timestamps come from the clock at the moment the frame
/// is read, not from the kernel's own hardware/software timestamp, so they run
/// a little late under load; that is fine for idle timeouts and wrong for
/// anything measuring inter-packet timing, which is why the pcap replay path
/// must use the file's own timestamps instead.
pub struct LiveSource {
    interface: String,
    /// in the future: BPF filter can b applied at the kernel, so uninteresting traffic never reaches
    /// user space.
    filter: Option<String>,
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
            interface,
            filter,
            link,
            receiver,
        })
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
                return Ok(Some(observation));
            }
        }
    }
}

fn find_interface(name: &str) -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();

    interfaces
        .iter()
        .find(|candidate| candidate.name == name)
        .cloned()
        .ok_or_else(|| {
            let available: Vec<&str> = interfaces.iter().map(|i| i.name.as_str()).collect();
            Error::Capture(format!(
                "no interface `{name}`; this host has: {}",
                available.join(", ")
            ))
        })
}

/// Point at the capability rather than the errno — a bare "permission denied"
/// out of a packet sniffer sends people to `sudo` when a capability is enough.
fn open_failed(interface: &str, source: io::Error) -> Error {
    if source.kind() == io::ErrorKind::PermissionDenied {
        return Error::Capture(format!(
            "cannot capture on `{interface}`: needs CAP_NET_RAW \
             (`sudo setcap cap_net_raw,cap_net_admin+eip <binary>`) or root"
        ));
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
