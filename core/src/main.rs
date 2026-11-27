mod control;
mod guard;
mod identity;
mod network;
mod portal;
mod portal_routes;
mod probe;
mod transport;
mod wifi;

use anyhow::{Context, Result, bail, ensure};
use control::Control;
use identity::Identity;
use network::Network;
use std::{
    ffi::c_int,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::net::{UnixListener, UnixStream},
    time::Duration,
};
use transport::Tunnel;

unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut c_int,
        count: *mut usize,
    ) -> c_int;
}

fn report(mut peer: &UnixStream, state: &str, detail: &str) -> Result<()> {
    serde_json::to_writer(
        &mut peer,
        &serde_json::json!({"state":state,"detail":detail,"supportsP2P":true}),
    )?;
    peer.write_all(b"\n")?;
    Ok(())
}

fn forward(
    tunnel: &mut Tunnel,
    network: &Network,
    control: &mut Control<'_>,
    until: Option<&std::sync::mpsc::Receiver<Result<()>>>,
) -> Result<()> {
    let mut frame = [0u8; 1282];
    let mut counts = [0_u64; 2];
    loop {
        if let Some(result) = until.and_then(|rx| rx.try_recv().ok()) {
            return result.with_context(|| {
                format!(
                    "Interface check handled {} outgoing and {} incoming packets",
                    counts[0], counts[1]
                )
            });
        }
        tunnel.set_p2p(control.p2p)?;
        tunnel.flush()?;
        let device_fd = if tunnel.accepts_packet() {
            network.device.as_raw_fd()
        } else {
            -1
        };
        let Some(events) = control.wait(
            &[tunnel.fd(), device_fd],
            if until.is_some() {
                tunnel.timeout().min(Duration::from_millis(100))
            } else {
                tunnel.timeout()
            },
        )?
        else {
            return Ok(());
        };
        tunnel.advance(events[0])?;
        tunnel.receive(|ip| match network.device.send(ip) {
            Ok(_) => {
                counts[1] += 1;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e.into()),
        })?;
        if events[1] {
            for _ in 0..64 {
                match network.device.recv(&mut frame[2..]) {
                    Ok(0) => bail!("Tunnel device closed"),
                    Ok(size) => {
                        counts[0] += 1;
                        tunnel.send(&frame[..size + 2])?;
                        if !tunnel.accepts_packet() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}

fn verify_interface(
    tunnel: &mut Tunnel,
    network: &Network,
    control: &mut Control<'_>,
    addresses: [&'static str; 2],
) -> Result<()> {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let check = || -> Result<()> {
            for address in addresses {
                let output = std::process::Command::new("/usr/bin/curl")
                    .env_clear()
                    .args([
                        "-q",
                        "--noproxy",
                        "*",
                        "--silent",
                        "--show-error",
                        "--fail",
                        "--max-time",
                        "5",
                        "--resolve",
                        &format!("one.one.one.one:443:{address}"),
                        "https://one.one.one.one/cdn-cgi/trace",
                    ])
                    .output()?;
                ensure!(
                    output.status.success(),
                    "Interface HTTPS check failed for {address}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                ensure!(
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .any(|line| matches!(line, "warp=on" | "warp=plus")),
                    "Cloudflare did not confirm WARP egress"
                );
            }
            Ok(())
        };
        let _ = send.send(check());
    });
    forward(tunnel, network, control, Some(&receive))?;
    ensure!(control.wait(&[], Duration::ZERO)?.is_some(), "Disconnected");
    Ok(())
}

fn serve(peer: &UnixStream) -> Result<()> {
    peer.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut line = Vec::new();
    BufReader::new(peer)
        .take(8193)
        .read_until(b'\n', &mut line)?;
    ensure!(
        line.len() <= 8192 && line.last() == Some(&b'\n'),
        "Incomplete registration"
    );
    let id: Identity = serde_json::from_slice(&line)?;
    id.validate()?;
    let mut control = Control::new(Some(peer));
    report(peer, "connecting", "Opening WARP tunnel")?;
    guard::Link::update(&id, None)?;
    Network::check_conflicts()?;
    let mut tunnel = Tunnel::dial(&id, &mut control)?;
    probe::verify(&mut tunnel, &id, &mut control)?;
    let mut network = Network::prepare(&id)?;
    guard::Link::update(&id, Some(&network.name))?;
    verify_interface(
        &mut tunnel,
        &network,
        &mut control,
        ["1.0.0.1", "[2606:4700:4700::1001]"],
    )?;
    network.claim(&id)?;
    verify_interface(
        &mut tunnel,
        &network,
        &mut control,
        ["1.1.1.1", "[2606:4700:4700::1111]"],
    )?;
    loop {
        report(peer, "connected", &network.name)?;
        match forward(&mut tunnel, &network, &mut control, None) {
            Ok(()) => return Ok(()),
            Err(error) => report(peer, "reconnecting", &error.to_string())?,
        }
        drop(tunnel);
        let mut delay = Duration::from_secs(1);
        loop {
            if control.wait(&[], delay)?.is_none() {
                return Ok(());
            }
            match Tunnel::dial(&id, &mut control).and_then(|mut candidate| {
                probe::verify(&mut candidate, &id, &mut control)?;
                network.verify_capture()?;
                verify_interface(
                    &mut candidate,
                    &network,
                    &mut control,
                    ["1.1.1.1", "[2606:4700:4700::1111]"],
                )?;
                Ok(candidate)
            }) {
                Ok(new) => {
                    tunnel = new;
                    break;
                }
                Err(error) => report(peer, "reconnecting", &error.to_string())?,
            }
            delay = (delay * 2).min(Duration::from_secs(15));
        }
    }
}

fn listener() -> Result<UnixListener> {
    let mut fds = std::ptr::null_mut();
    let mut count = 0;
    let error = unsafe { launch_activate_socket(c"Control".as_ptr(), &mut fds, &mut count) };
    ensure!(
        error == 0,
        "Install the OpenWARP package to activate the tunnel helper"
    );
    ensure!(count == 1, "Expected one launchd socket");
    let listener = unsafe { UnixListener::from_raw_fd(*fds) };
    unsafe { libc::free(fds.cast()) };
    Ok(listener)
}

fn activate() -> Result<()> {
    guard::restore()?;
    let (peer, _) = listener()?.accept()?;
    if let Err(error) = serve(&peer) {
        let _ = report(&peer, "error", &format!("{error:#}"));
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => activate(),
        [cmd] if cmd == "wifi-login" => {
            if let Err(error) = portal::supervise() {
                println!("{}", serde_json::json!({"error":error.to_string()}));
            }
            Ok(())
        }
        [cmd] if cmd == "wifi-relay" => {
            if let Err(error) = portal::run() {
                println!("{}", serde_json::json!({"error":error.to_string()}));
            }
            Ok(())
        }
        [cmd] if cmd == "guard-control" => guard::serve(listener()?.accept()?.0),
        [cmd, action] if cmd == "kill-switch" => guard::request(action),
        [command, path] if command == "probe-interface" => {
            let data = fs::read(path)?;
            let id = serde_json::from_slice(&data)?;
            let mut control = Control::new(None);
            let mut tunnel = Tunnel::dial(&id, &mut control)?;
            let network = Network::prepare(&id)?;
            verify_interface(
                &mut tunnel,
                &network,
                &mut control,
                ["1.0.0.1", "[2606:4700:4700::1001]"],
            )?;
            println!("Verified IPv4 and IPv6 HTTPS over {}.", network.name);
            Ok(())
        }
        [command, path] if command == "probe" => {
            let data = fs::read(path).context("Read OpenWARP enrollment")?;
            let id = serde_json::from_slice(&data)?;
            let mut control = Control::new(None);
            let mut tunnel = Tunnel::dial(&id, &mut control)?;
            probe::verify(&mut tunnel, &id, &mut control)?;
            println!(
                "WARP CONNECT-IP verified: TLS 1.3, P256Kyber768Draft00, pinned peer, IPv4 and IPv6 DNS answers."
            );
            Ok(())
        }
        _ => bail!("Usage: openwarp-tunnel probe <identity.json>"),
    }
}
