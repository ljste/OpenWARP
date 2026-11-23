use crate::identity::Identity;
use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::{CString, c_void},
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, RawFd},
    process::Command,
    time::Duration,
};
use tun::AbstractDevice;

unsafe extern "C" {
    fn openwarp_dns_open(interface: *const libc::c_char) -> *mut c_void;
    fn openwarp_dns_close(session: *mut c_void);
}

fn output(tool: &str, args: &[&str]) -> Result<String> {
    let result = Command::new(tool).args(args).env("LC_ALL", "C").output()?;
    ensure!(
        result.status.success(),
        "{} {}",
        tool,
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(String::from_utf8(result.stdout)?)
}

pub fn route(family: &str, dest: &str) -> Result<String> {
    let text = output("/sbin/route", &["-n", "get", family, dest])?;
    text.lines()
        .find_map(|s| {
            s.trim()
                .strip_prefix("interface:")
                .map(|i| i.trim().to_owned())
        })
        .context("No network interface on route")
}

pub fn physical_socket(edge: IpAddr) -> Result<UdpSocket> {
    let (family, bind, level, option) = if edge.is_ipv4() {
        ("-inet", "0.0.0.0:0", libc::IPPROTO_IP, libc::IP_BOUND_IF)
    } else {
        ("-inet6", "[::]:0", libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    };
    let iface = CString::new(route(family, "default")?)?;
    ensure!(
        !iface.as_bytes().starts_with(b"utun"),
        "Default route belongs to another VPN"
    );
    let sock = UdpSocket::bind(bind)?;
    // Keep transport traffic on the uplink selected for this session.
    let index = unsafe { libc::if_nametoindex(iface.as_ptr()) };
    ensure!(index != 0, "Uplink disappeared");
    let result = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            option,
            (&raw const index).cast(),
            size_of_val(&index) as _,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    sock.connect(SocketAddr::new(edge, 443))?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

pub fn ready(fds: &[RawFd], wait: Duration) -> Result<[bool; 3]> {
    assert!(fds.len() <= 3);
    let mut events = [libc::pollfd {
        fd: -1,
        events: libc::POLLIN,
        revents: 0,
    }; 3];
    for (entry, fd) in events.iter_mut().zip(fds) {
        entry.fd = *fd;
    }
    let timeout = wait.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(events.as_mut_ptr(), events.len() as _, timeout) };
    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(io::Error::last_os_error().into());
    }
    Ok(events.map(|entry| entry.revents != 0))
}

pub struct Network {
    pub device: tun::Device,
    pub name: String,
    dns: *mut c_void,
}

impl Network {
    pub fn check_conflicts() -> Result<()> {
        for (family, dest) in [
            ("-inet", "1.1.1.1"),
            ("-inet", "8.8.8.8"),
            ("-inet6", "2606:4700:4700::1111"),
        ] {
            if route(family, dest).is_ok_and(|i| i.starts_with("utun")) {
                bail!("Disconnect the other VPN before connecting OpenWARP.");
            }
        }
        Ok(())
    }

    pub fn prepare(id: &Identity) -> Result<Self> {
        let mut config = tun::Configuration::default();
        config.platform_config(|platform| {
            platform.enable_routing(false);
        });
        config.mtu(1280).up();
        let device = tun::create(&config).context("Create macOS utun")?;
        let name = device.tun_name()?;
        device.set_nonblock()?;
        let address = id.ipv4.to_string();
        output(
            "/sbin/ifconfig",
            &[
                &name,
                "inet",
                &address,
                &address,
                "netmask",
                "255.255.255.255",
                "up",
            ],
        )?;
        output(
            "/sbin/ifconfig",
            &[
                &name,
                "inet6",
                &id.ipv6.to_string(),
                "prefixlen",
                "128",
                "alias",
            ],
        )?;
        for (family, address) in [("-inet", "1.0.0.1"), ("-inet6", "2606:4700:4700::1001")] {
            output(
                "/sbin/route",
                &["-n", "add", family, "-host", address, "-interface", &name],
            )?;
        }
        Ok(Self {
            device,
            name,
            dns: std::ptr::null_mut(),
        })
    }

    pub fn claim(&mut self, id: &Identity) -> Result<()> {
        let name = &self.name;
        // Interface-owned routes vanish on close. Leave both MASQUE peers on the physical default.
        for edge in [IpAddr::V4(id.endpoint4), IpAddr::V6(id.endpoint6)] {
            let family = if edge.is_ipv4() { "-inet" } else { "-inet6" };
            for (prefix, bits) in capture_prefixes(edge) {
                output(
                    "/sbin/route",
                    &[
                        "-n",
                        "add",
                        family,
                        &format!("{prefix}/{bits}"),
                        "-interface",
                        name,
                    ],
                )?;
            }
            if let Ok(actual) = route(family, &edge.to_string()) {
                ensure!(
                    actual != *name,
                    "MASQUE endpoint would route back into OpenWARP"
                );
            }
        }
        let dns = unsafe { openwarp_dns_open(CString::new(name.as_str())?.as_ptr()) };
        ensure!(!dns.is_null(), "macOS refused the OpenWARP DNS service");
        self.dns = dns;
        self.verify_capture()
    }

    pub fn verify_capture(&self) -> Result<()> {
        let name = &self.name;
        for (family, dest) in [
            ("-inet", "1.1.1.1"),
            ("-inet", "8.8.8.8"),
            ("-inet6", "2606:4700:4700::1111"),
        ] {
            ensure!(
                route(family, dest)? == *name,
                "Another service controls the {} route",
                dest
            );
        }
        for _ in 0..20 {
            if default_dns_is_openwarp(&output("/usr/sbin/scutil", &["--dns"])?) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(75));
        }
        bail!("macOS did not select the OpenWARP DNS resolver")
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        if !self.dns.is_null() {
            unsafe { openwarp_dns_close(self.dns) };
        }
    }
}

fn capture_prefixes(edge: IpAddr) -> Vec<(IpAddr, u8)> {
    let (value, width) = match edge {
        IpAddr::V4(v) => (u128::from(u32::from(v)), 32),
        IpAddr::V6(v) => (u128::from(v), 128),
    };
    (1..=width)
        .map(|length| {
            let shift = width - length;
            let sibling = ((value >> shift) ^ 1) << shift;
            let prefix = if edge.is_ipv4() {
                IpAddr::V4((sibling as u32).into())
            } else {
                IpAddr::V6(sibling.into())
            };
            (prefix, length)
        })
        .collect()
}

fn default_dns_is_openwarp(output: &str) -> bool {
    let mut servers = output
        .lines()
        .skip_while(|line| line.trim() != "resolver #1")
        .skip(1)
        .take_while(|line| !line.trim().starts_with("resolver #"))
        .filter(|line| line.trim().starts_with("nameserver["))
        .filter_map(|line| line.split_once(" : ").map(|(_, value)| value.trim()))
        .peekable();
    servers.peek().is_some()
        && servers.all(|ip| {
            matches!(
                ip,
                "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{capture_prefixes, default_dns_is_openwarp};
    use std::net::IpAddr;

    #[test]
    fn capture_covers_every_address_except_its_transport_peer() {
        for (peer, width) in [("162.159.198.2", 32_u8), ("2606:4700:103::2", 128)] {
            let addr: IpAddr = peer.parse().unwrap();
            let as_num = |ip: IpAddr| match ip {
                IpAddr::V4(v) => u128::from(u32::from(v)),
                IpAddr::V6(v) => u128::from(v),
            };
            let prefixes = capture_prefixes(addr);
            let mut ranges = prefixes
                .iter()
                .map(|(p, len)| {
                    let first = as_num(*p);
                    (first, first + ((1_u128 << (width - len)) - 1))
                })
                .collect::<Vec<_>>();
            ranges.push((as_num(addr), as_num(addr)));
            ranges.sort_unstable();
            assert_eq!(ranges[0].0, 0);
            assert_eq!(
                ranges.last().unwrap().1,
                if width == 128 {
                    u128::MAX
                } else {
                    u32::MAX.into()
                }
            );
            assert!(ranges.windows(2).all(|w| w[0].1 + 1 == w[1].0));
        }
    }

    #[test]
    fn default_resolver_must_contain_only_cloudflare_addresses() {
        assert!(default_dns_is_openwarp(
            "resolver #1\n nameserver[0] : 2606:4700:4700::1111\nresolver #2\n nameserver[0] : 10.0.0.1"
        ));
        assert!(!default_dns_is_openwarp(
            "resolver #1\n nameserver[0] : 1.1.1.1\n nameserver[1] : 10.0.0.1"
        ));
        assert!(!default_dns_is_openwarp("no resolver"));
    }
}
