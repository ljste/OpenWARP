use crate::portal_routes::PortalRoutes;
use crate::wifi::Wifi;
use anyhow::{Context, Result, ensure};
use boring::rand::rand_bytes;
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream},
    os::fd::AsRawFd,
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

pub fn supervise() -> Result<()> {
    let wifi = Wifi::current()?;
    let _routes = PortalRoutes::open(&wifi.name)?;
    let status = Command::new(std::env::current_exe()?)
        .arg("wifi-relay")
        .env_clear()
        .status()?;
    ensure!(status.success(), "The Wi-Fi sign-in service stopped");
    Ok(())
}

fn enter_service_account() -> Result<()> {
    let user = unsafe { libc::getpwnam(c"nobody".as_ptr()).as_ref() }
        .context("Missing sign-in service account")?;
    let uid = user.pw_uid;
    let group = unsafe { libc::getgrnam(c"_openwarpportal".as_ptr()).as_ref() }
        .context("Missing sign-in service group")?;
    let gid = group.gr_gid;
    ensure!(uid != 0 && gid != 0, "Invalid sign-in service account");
    // Darwin includes the effective group in the process group list.
    if unsafe { libc::setgid(gid) != 0 || libc::setgroups(1, &gid) != 0 || libc::setuid(uid) != 0 }
    {
        return Err(io::Error::last_os_error()).context("Enter Wi-Fi sign-in service account");
    }
    ensure!(
        unsafe {
            libc::getuid() == uid
                && libc::geteuid() == uid
                && libc::getgid() == gid
                && libc::getegid() == gid
        },
        "Invalid Wi-Fi relay credentials"
    );
    Ok(())
}

fn read_bytes<const N: usize>(stream: &mut TcpStream) -> io::Result<[u8; N]> {
    let mut data = [0; N];
    stream.read_exact(&mut data)?;
    Ok(data)
}

fn field(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let [n] = read_bytes(stream)?;
    let mut buf = vec![0; n as usize];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn relay(mut client: TcpStream, wifi: &Wifi, secret: &str) -> Result<()> {
    client.set_nonblocking(false)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    ensure!(read_bytes::<1>(&mut client)? == [5], "SOCKS version");
    if !field(&mut client)?.contains(&2) {
        client.write_all(&[5, 255])?;
        return Ok(());
    }
    client.write_all(&[5, 2])?;
    let authenticated = read_bytes::<1>(&mut client)? == [1]
        && field(&mut client)? == b"openwarp"
        && field(&mut client)? == secret.as_bytes();
    client.write_all(&[1, u8::from(!authenticated)])?;
    ensure!(authenticated, "Authentication failed");
    let [version, cmd, reserved, address_type] = read_bytes(&mut client)?;
    ensure!(
        (version, cmd, reserved) == (5, 1, 0),
        "Only web connections are supported"
    );
    let host = match address_type {
        1 => Ipv4Addr::from(read_bytes::<4>(&mut client)?).to_string(),
        4 => Ipv6Addr::from(read_bytes::<16>(&mut client)?).to_string(),
        3 => String::from_utf8(field(&mut client)?)?,
        _ => anyhow::bail!("Unknown proxy address type"),
    };
    let port = u16::from_be_bytes(read_bytes(&mut client)?);
    let remote = wifi.connect(&host, port);
    client.write_all(&[
        5,
        if remote.is_ok() { 0 } else { 4 },
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ])?;
    let mut remote = remote?;
    client.set_read_timeout(None)?;
    let mut to_client = client.try_clone()?;
    let mut from_remote = remote.try_clone()?;
    thread::scope(|scope| {
        scope.spawn(move || {
            let _ = io::copy(&mut from_remote, &mut to_client);
            let _ = to_client.shutdown(Shutdown::Write);
        });
        let _ = io::copy(&mut client, &mut remote);
        let _ = remote.shutdown(Shutdown::Write);
    });
    Ok(())
}

pub fn run() -> Result<()> {
    enter_service_account()?;
    let wifi = Arc::new(Wifi::current()?);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let mut bytes = [0; 32];
    rand_bytes(&mut bytes)?;
    let secret = Arc::new(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let api = Command::new("/usr/sbin/ipconfig")
        .args(["getoption", &wifi.name, "captive_portal_url"])
        .output()?;
    let config = serde_json::json!({"port":listener.local_addr()?.port(), "secret":*secret,
                                   "api":String::from_utf8_lossy(&api.stdout).trim()});
    writeln!(io::stdout().lock(), "{config}")?;
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let events = crate::network::ready(&[0, listener.as_raw_fd()], remaining)?;
        if events[0] {
            break;
        }
        if events[1] {
            let client = match listener.accept() {
                Ok((client, _)) => client,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e).context("Accept sign-in connection"),
            };
            if Arc::strong_count(&wifi) > 40 {
                continue;
            }
            let (wifi, secret) = (wifi.clone(), secret.clone());
            thread::spawn(move || {
                let _ = relay(client, &wifi, &secret);
            });
        }
    }
    Ok(())
}
