use crate::{identity::Identity, network::ready, transport::Tunnel};
use anyhow::{Result, ensure};
use boring::rand::rand_bytes;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use std::{
    net::Ipv6Addr,
    os::fd::RawFd,
    time::{Duration, Instant},
};

pub fn verify(tunnel: &mut Tunnel, id: &Identity, control: RawFd) -> Result<()> {
    let mut random = [0; 4];
    rand_bytes(&mut random)?;
    let tx = &random[..2];
    let port = 49152 + u16::from_be_bytes([random[2], random[3]]) % 16384;
    let mut query = tx.to_vec();
    query.extend_from_slice(
        b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    );
    let resolver6: Ipv6Addr = "2606:4700:4700::1111".parse()?;
    let mut frames = [vec![0, 0], vec![0, 0]];
    PacketBuilder::ipv4(id.ipv4.octets(), [1, 1, 1, 1], 64)
        .udp(port, 53)
        .write(&mut frames[0], &query)?;
    PacketBuilder::ipv6(id.ipv6.octets(), resolver6.octets(), 64)
        .udp(port, 53)
        .write(&mut frames[1], &query)?;
    let mut received = [false, false];
    for _ in 0..3 {
        for (index, frame) in frames.iter().enumerate() {
            if !received[index] {
                tunnel.send(frame)?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            tunnel.flush()?;
            let events = ready(
                &[tunnel.fd(), control],
                tunnel
                    .timeout()
                    .min(deadline.saturating_duration_since(Instant::now())),
            )?;
            ensure!(!events[1], "Disconnected");
            tunnel.advance(events[0])?;
            tunnel.receive(|bytes| {
                let Ok(packet) = SlicedPacket::from_ip(bytes) else {
                    return Ok(());
                };
                let Some(TransportSlice::Udp(udp)) = packet.transport else {
                    return Ok(());
                };
                let dns = udp.payload();
                if udp.source_port() == 53
                    && udp.destination_port() == port
                    && dns.len() >= 12
                    && &dns[..2] == tx
                    && dns[2] & 0x80 != 0
                    && dns[3] & 15 == 0
                    && dns[6..8] != [0, 0]
                {
                    received[usize::from(bytes[0] >> 4 == 6)] = true;
                }
                Ok(())
            })?;
            if received == [true, true] {
                return Ok(());
            }
        }
    }
    anyhow::bail!(
        "WARP DNS probe failed (IPv4 {}, IPv6 {})",
        received[0],
        received[1]
    )
}
