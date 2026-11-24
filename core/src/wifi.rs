use anyhow::{Context, Result, bail, ensure};
use boring::rand::rand_bytes;
use serde::Deserialize;
use simple_dns::{CLASS, Name, Packet, PacketFlag, Question, TYPE, rdata::RData};
use socket2::{Domain, Socket, Type};
use std::{
    ffi::{CStr, CString},
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    num::NonZeroU32,
    time::Duration,
};

unsafe extern "C" {
    fn openwarp_wifi_dns() -> *mut libc::c_char;
}

#[derive(Deserialize)]
struct Service {
    interface: String,
    servers: Vec<String>,
}

pub struct Wifi {
    pub name: String,
    index: NonZeroU32,
    servers: Vec<SocketAddr>,
}

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
pub const WEB_PORTS: &[u16] = &[80, 443, 8000, 8080, 8443, 8843, 8880];

impl Wifi {
    pub fn current() -> Result<Self> {
        let data = unsafe { openwarp_wifi_dns() };
        ensure!(
            !data.is_null(),
            "Join a Wi-Fi network with a DNS server first."
        );
        let service = serde_json::from_slice::<Service>(unsafe { CStr::from_ptr(data).to_bytes() });
        unsafe { libc::free(data.cast()) };
        let service = service?;
        let name = CString::new(service.interface.as_str())?;
        let index = NonZeroU32::new(unsafe { libc::if_nametoindex(name.as_ptr()) })
            .context("Wi-Fi disconnected")?;
        let mut servers = Vec::new();
        for address in service.servers {
            let ip: IpAddr = address.split('%').next().unwrap_or("").parse()?;
            if !ip.is_loopback() && !ip.is_unspecified() {
                servers.push(Self::address(ip, 53, index));
            }
        }
        ensure!(!servers.is_empty(), "Wi-Fi has no usable resolver");
        Ok(Self {
            name: service.interface,
            index,
            servers,
        })
    }

    fn address(ip: IpAddr, port: u16, index: NonZeroU32) -> SocketAddr {
        let mut addr = SocketAddr::new(ip, port);
        if let SocketAddr::V6(v6) = &mut addr
            && v6.ip().is_unicast_link_local()
        {
            v6.set_scope_id(index.get());
        }
        addr
    }

    fn socket(&self, address: SocketAddr, kind: Type) -> Result<Socket> {
        let sock = Socket::new(Domain::for_address(address), kind, None)?;
        if address.is_ipv4() {
            sock.bind_device_by_index_v4(Some(self.index))?;
        } else {
            sock.bind_device_by_index_v6(Some(self.index))?;
        }
        Ok(sock)
    }

    fn addresses(&self, host: &str, kind: TYPE, server: SocketAddr) -> Result<Vec<IpAddr>> {
        let mut random = [0; 2];
        rand_bytes(&mut random)?;
        let mut query = Packet::new_query(u16::from_be_bytes(random));
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        query.questions.push(Question::new(
            Name::new(host)?,
            kind.into(),
            CLASS::IN.into(),
            false,
        ));
        let wire = query.build_bytes_vec()?;
        let udp: UdpSocket = self.socket(server, Type::DGRAM)?.into();
        udp.set_read_timeout(Some(DNS_TIMEOUT))?;
        udp.connect(server)?;
        udp.send(&wire)?;
        let mut answer = vec![0; 4096];
        let size = udp.recv(&mut answer)?;
        answer.truncate(size);
        if Packet::parse(&answer)?.has_flags(PacketFlag::TRUNCATION) {
            let sock = self.socket(server, Type::STREAM)?;
            sock.connect_timeout(&server.into(), DNS_TIMEOUT)?;
            let mut tcp: TcpStream = sock.into();
            tcp.set_read_timeout(Some(DNS_TIMEOUT))?;
            tcp.write_all(&(wire.len() as u16).to_be_bytes())?;
            tcp.write_all(&wire)?;
            let mut length = [0; 2];
            tcp.read_exact(&mut length)?;
            answer.resize(u16::from_be_bytes(length).into(), 0);
            tcp.read_exact(&mut answer)?;
        }
        let reply = Packet::parse(&answer)?;
        ensure!(
            reply.id() == query.id()
                && reply.has_flags(PacketFlag::RESPONSE)
                && matches!(reply.questions.as_slice(), [q] if q.qname.to_string().eq_ignore_ascii_case(host.trim_end_matches('.')) && q.qtype == kind.into() && q.qclass == CLASS::IN.into()),
            "Unexpected Wi-Fi DNS answer"
        );
        let mut name = host.trim_end_matches('.').to_lowercase();
        for _ in 0..12 {
            let records = reply
                .answers
                .iter()
                .filter(|r| r.name.to_string().eq_ignore_ascii_case(&name));
            let mut alias = None;
            let mut ips = Vec::new();
            for r in records {
                match &r.rdata {
                    RData::A(a) if kind == TYPE::A => ips.push(IpAddr::V4(a.address.into())),
                    RData::AAAA(a) if kind == TYPE::AAAA => ips.push(IpAddr::V6(a.address.into())),
                    RData::CNAME(c) => alias = Some(c.0.to_string()),
                    _ => (),
                }
            }
            if !ips.is_empty() || alias.is_none() {
                return Ok(ips);
            }
            name = alias.unwrap();
        }
        bail!("Wi-Fi DNS alias loop")
    }

    fn connect_ip(&self, ip: IpAddr, port: u16) -> Result<TcpStream> {
        let ip = ip.to_canonical();
        ensure!(
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !matches!(ip, IpAddr::V4(v) if v.is_broadcast() || v.octets()[0] == 0),
            "Local device address"
        );
        let address = Self::address(ip, port, self.index);
        ensure!(
            TcpListener::bind(Self::address(ip, 0, self.index)).is_err(),
            "Local device address"
        );
        let sock = self.socket(address, Type::STREAM)?;
        sock.connect_timeout(&address.into(), Duration::from_secs(3))?;
        Ok(sock.into())
    }

    pub fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        ensure!(WEB_PORTS.contains(&port), "Unsupported sign-in port");
        if let Ok(ip) = host.parse() {
            return self.connect_ip(ip, port);
        }
        for &server in self.servers.iter().take(3) {
            for kind in [TYPE::A, TYPE::AAAA] {
                for ip in self
                    .addresses(host, kind, server)
                    .unwrap_or_default()
                    .into_iter()
                    .take(4)
                {
                    if let Ok(stream) = self.connect_ip(ip, port) {
                        return Ok(stream);
                    }
                }
            }
        }
        bail!("Cannot reach sign-in host on Wi-Fi")
    }
}
