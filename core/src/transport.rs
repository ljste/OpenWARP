use crate::{control::Control, identity::Identity, network::physical_socket};
use anyhow::{Context, Result, bail, ensure};
use boring::rand::rand_bytes;
use quiche::h3::{self, Header, NameValue};
use socket2::SockRef;
use std::{
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, RawFd},
    time::{Duration, Instant},
};

pub struct Tunnel {
    socket: UdpSocket,
    default_receive_buffer: usize,
    p2p: bool,
    local: SocketAddr,
    remote: SocketAddr,
    conn: quiche::Connection,
    http: Option<h3::Connection>,
    admitted: bool,
    last_ping: Instant,
}

impl Tunnel {
    pub fn dial(id: &Identity, control: &mut Control<'_>) -> Result<Self> {
        let endpoints = [IpAddr::V4(id.endpoint4), IpAddr::V6(id.endpoint6)];
        let mut errors = Vec::new();
        for edge in endpoints {
            if control.wait(&[], Duration::ZERO)?.is_none() {
                bail!("Disconnected");
            }
            match Self::open(id, edge, control) {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) => errors.push(format!("{edge}: {error:#}")),
            }
        }
        bail!("WARP handshake failed. {}", errors.join("; "))
    }

    fn open(id: &Identity, edge: IpAddr, control: &mut Control<'_>) -> Result<Self> {
        let socket = physical_socket(edge)?;
        let local = socket.local_addr()?;
        let remote = socket.peer_addr()?;
        let mut cfg = id.transport_config()?;
        let mut cid = [0_u8; quiche::MAX_CONN_ID_LEN];
        rand_bytes(&mut cid)?;
        let conn = quiche::connect(
            Some("consumer-masque.cloudflareclient.com"),
            &quiche::ConnectionId::from_ref(&cid),
            local,
            remote,
            &mut cfg,
        )?;
        let mut peer = Self {
            default_receive_buffer: SockRef::from(&socket).recv_buffer_size()?,
            p2p: false,
            socket,
            local,
            remote,
            conn,
            http: None,
            admitted: false,
            last_ping: Instant::now(),
        };
        let deadline = Instant::now() + Duration::from_secs(6);
        while !peer.admitted {
            peer.flush()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "Timed out waiting for Cloudflare");
            let events = control
                .wait(&[peer.fd()], remaining.min(peer.timeout()))?
                .context("Disconnected")?;
            peer.advance(events[0])?;
        }
        ensure!(
            peer.conn.dgram_max_writable_len().unwrap_or(0) >= 1282,
            "MASQUE datagram size cannot carry IPv6 MTU"
        );
        Ok(peer)
    }

    pub fn set_p2p(&mut self, enabled: bool) -> Result<()> {
        if self.p2p == enabled {
            return Ok(());
        }
        let socket = SockRef::from(&self.socket);
        if enabled {
            // Respect the host's socket limit and keep its default if it is already larger.
            for size in [4 << 20, 2 << 20, 1 << 20] {
                if size <= self.default_receive_buffer || socket.set_recv_buffer_size(size).is_ok()
                {
                    break;
                }
            }
        } else {
            socket.set_recv_buffer_size(self.default_receive_buffer)?;
        }
        self.p2p = enabled;
        Ok(())
    }

    pub fn accepts_packet(&self) -> bool {
        !self.p2p || !self.conn.is_dgram_send_queue_full()
    }

    pub fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    pub fn timeout(&self) -> Duration {
        let ping =
            (self.last_ping + Duration::from_secs(20)).saturating_duration_since(Instant::now());
        self.conn.timeout().unwrap_or(ping).min(ping)
    }

    pub fn flush(&mut self) -> Result<()> {
        let mut buffer = [0u8; 1500];
        loop {
            match self.conn.send(&mut buffer) {
                Ok((len, _)) => match self.socket.send(&buffer[..len]) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    result => {
                        result?;
                    }
                },
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    pub fn advance(&mut self, readable: bool) -> Result<()> {
        if readable {
            let mut buf = [0u8; 65535];
            for _ in 0..64 {
                let size = match self.socket.recv(&mut buf) {
                    Ok(size) => size,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                };
                match self.conn.recv(
                    &mut buf[..size],
                    quiche::RecvInfo {
                        from: self.remote,
                        to: self.local,
                    },
                ) {
                    Ok(_) | Err(quiche::Error::Done) => (),
                    Err(e) => return Err(e).context("QUIC receive"),
                }
            }
        }
        if self.conn.timeout().is_some_and(|d| d.is_zero()) {
            self.conn.on_timeout();
        }
        ensure!(
            !self.conn.is_closed() && !self.conn.is_draining(),
            "WARP connection closed"
        );
        if !self.conn.is_established() {
            return Ok(());
        }
        if self.last_ping.elapsed() >= Duration::from_secs(20) {
            self.conn.send_ack_eliciting()?;
            self.last_ping = Instant::now();
        }
        if self.http.is_none() {
            let mut cfg = h3::Config::new()?;
            cfg.enable_extended_connect(true);
            let mut http = h3::Connection::with_transport(&mut self.conn, &cfg)?;
            let headers = [
                Header::new(b":method", b"CONNECT"),
                Header::new(b":protocol", b"cf-connect-ip"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", b"cloudflareaccess.com"),
                Header::new(b":path", b"/"),
                Header::new(b"capsule-protocol", b"?1"),
                Header::new(b"user-agent", b""),
            ];
            ensure!(
                http.send_request(&mut self.conn, &headers, false)? == 0,
                "Unexpected CONNECT stream"
            );
            self.http = Some(http);
        }
        let http = self.http.as_mut().context("Missing HTTP/3 connection")?;
        loop {
            match http.poll(&mut self.conn) {
                Ok((0, h3::Event::Headers { list, .. })) => {
                    let status = list
                        .iter()
                        .find(|h| h.name() == b":status")
                        .context("No CONNECT status")?;
                    ensure!(
                        status.value() == b"200",
                        "Cloudflare rejected CONNECT-IP ({})",
                        String::from_utf8_lossy(status.value())
                    );
                    self.admitted = true;
                }
                Ok((0, h3::Event::Data)) => {
                    let mut capsule = [0u8; 2048];
                    while http
                        .recv_body(&mut self.conn, 0, &mut capsule)
                        .is_ok_and(|n| n > 0)
                    {}
                }
                Ok((0, h3::Event::Finished | h3::Event::Reset(_))) => {
                    bail!("Cloudflare closed the CONNECT stream")
                }
                Ok(_) => (),
                Err(h3::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    pub fn send(&mut self, frame: &[u8]) -> Result<()> {
        // The only request is stream zero, so the flow ID and context ID each encode as zero.
        ensure!(
            frame.starts_with(&[0, 0]) && frame.len() <= 1282,
            "Invalid CONNECT-IP datagram"
        );
        match self.conn.dgram_send(frame) {
            Ok(()) | Err(quiche::Error::Done) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn receive(&mut self, mut accept: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        loop {
            match self.conn.dgram_recv_buf() {
                Ok(frame)
                    if frame.len() > 2
                        && frame[..2] == [0, 0]
                        && matches!(frame[2] >> 4, 4 | 6) =>
                {
                    accept(&frame[2..])?
                }
                Ok(_) => (),
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }
}
