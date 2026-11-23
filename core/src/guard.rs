use crate::identity::Identity;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::{fd::AsRawFd, unix::net::UnixStream},
    process::{Command, Stdio},
    time::Duration,
};

const MODE: &str = "/var/db/io.github.ljste.openwarp.kill-switch";
const CONTEXT: &str = "/var/run/io.github.ljste.openwarp.context";
const TOKEN: &str = "/var/run/io.github.ljste.openwarp.pf-token";
const LOCK: &str = "/var/run/io.github.ljste.openwarp.guard-lock";
const SOCKET: &str = "/var/run/io.github.ljste.openwarp.guard.sock";
const ANCHOR: &str = "com.apple/000.OpenWARP";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Off,
    Standby,
    Armed,
}

impl Mode {
    fn load() -> Result<Self> {
        match fs::read_to_string(MODE).as_deref() {
            Ok("armed") => Ok(Self::Armed),
            Ok("standby") => Ok(Self::Standby),
            Ok("off") => Ok(Self::Off),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::Off),
            _ => bail!("Cannot read the OpenWARP kill switch setting"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Standby => "standby",
            Self::Off => "off",
        }
    }

    fn next(self, action: &str) -> Result<Self> {
        Ok(match action {
            "enable" if self == Self::Off => Self::Standby,
            "enable" => self,
            "pause" if self != Self::Off => Self::Standby,
            "enable-active" => Self::Armed,
            "arm" if self != Self::Off => Self::Armed,
            "arm" | "pause" | "disable" => Self::Off,
            _ => bail!("Unknown kill switch command"),
        })
    }
}

#[derive(Deserialize, Serialize)]
pub struct Link {
    endpoint4: Ipv4Addr,
    endpoint6: Ipv6Addr,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    interface: Option<String>,
}

impl Link {
    pub fn update(id: &Identity, name: Option<&str>) -> Result<()> {
        let _lock = lock()?;
        let link = Self {
            endpoint4: id.endpoint4,
            endpoint6: id.endpoint6,
            ipv4: id.ipv4,
            ipv6: id.ipv6,
            interface: name.map(String::from),
        };
        atomic_write(CONTEXT, &serde_json::to_vec(&link)?)?;
        if Mode::load()? == Mode::Armed {
            enforce(Some(&link), false)?;
        }
        Ok(())
    }
}

fn lock() -> Result<File> {
    let file = File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(LOCK)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(file)
}

fn atomic_write(path: &str, data: &[u8]) -> Result<()> {
    let temp = format!("{path}.new");
    let mut file = File::create(&temp)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    Ok(())
}

fn pf(args: &[&str], rules: Option<&str>) -> Result<String> {
    let mut child = Command::new("/sbin/pfctl")
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if rules.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(text) = rules {
        child
            .stdin
            .take()
            .context("Open pfctl input")?
            .write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    let err = String::from_utf8_lossy(&out.stderr);
    ensure!(out.status.success(), "Packet filter: {}", err.trim());
    Ok(format!("{}{}", String::from_utf8_lossy(&out.stdout), err))
}

fn rules(link: Option<&Link>) -> Result<String> {
    let mut text = String::from("pass quick on lo0 all no state\n");
    if let Some(link) = link {
        if let Some(name) = &link.interface {
            ensure!(
                name.strip_prefix("utun")
                    .and_then(|n| n.parse::<u32>().ok())
                    .is_some(),
                "Invalid tunnel interface"
            );
            for ip in [link.ipv4.to_string(), link.ipv6.to_string()] {
                text += &format!(
                    "pass out quick on {name} from {ip} to any no state\npass in quick on {name} from any to {ip} no state\n"
                );
            }
        }
        for edge in [link.endpoint4.to_string(), link.endpoint6.to_string()] {
            text += &format!(
                "pass out quick proto udp from any to {edge} port 443 user root keep state (if-bound)\n"
            );
        }
    }
    text += "pass out quick inet proto udp from any port 68 to any port 67 no state\n\
             pass in quick inet proto udp from any port 67 to any port 68 no state\n\
             pass out quick inet6 proto udp from any port 546 to ff02::1:2 port 547 no state\n\
             pass in quick inet6 proto udp from fe80::/10 port 547 to any port 546 no state\n\
             pass quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } no state\n\
             block drop quick all\n";
    Ok(text)
}

fn enforce(link: Option<&Link>, fresh: bool) -> Result<()> {
    let filter = pf(&["-sr"], None)?;
    let first = filter
        .lines()
        .find(|s| s.starts_with("anchor ") || s.starts_with("pass ") || s.starts_with("block "));
    ensure!(
        first == Some("anchor \"com.apple/*\" all"),
        "Unsupported PF configuration: expected the standard macOS filter anchor"
    );
    let interfaces = pf(&["-v", "-s", "Interfaces"], None)?;
    ensure!(
        !interfaces
            .lines()
            .any(|line| line.contains("skip") && line.split_whitespace().next() != Some("lo0")),
        "Unsupported PF configuration: an interface bypasses filtering"
    );
    pf(&["-a", ANCHOR, "-f", "-"], Some(&rules(link)?))?;
    let acquire = !std::path::Path::new(TOKEN).exists()
        || !pf(&["-si"], None)?
            .lines()
            .any(|line| line.starts_with("Status: Enabled"));
    if acquire {
        let output = pf(&["-E"], None)?;
        let token: u64 = output
            .lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.trim() == "Token")
                    .map(|(_, v)| v)
            })
            .context("Missing PF enable token")?
            .trim()
            .parse()?;
        atomic_write(TOKEN, token.to_string().as_bytes())?;
    }
    if fresh || acquire {
        // Existing floating states can otherwise pass traffic ahead of the block rule.
        pf(&["-F", "states"], None)?;
    }
    Ok(())
}

fn clear() -> Result<()> {
    pf(&["-a", ANCHOR, "-F", "rules"], None)?;
    match fs::read_to_string(TOKEN) {
        Ok(token) => {
            let number: u64 = token.trim().parse()?;
            pf(&["-X", &number.to_string()], None)?;
            fs::remove_file(TOKEN)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn context() -> Result<Option<Link>> {
    match fs::read(CONTEXT) {
        Ok(data) => Ok(Some(serde_json::from_slice(&data)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn change(action: &str) -> Result<()> {
    let _lock = lock()?;
    let old = Mode::load()?;
    let next = old.next(action)?;
    if old == next {
        return Ok(());
    }
    let link = context()?;
    atomic_write(MODE, next.name().as_bytes())?;
    let applied = match (old, next) {
        (_, Mode::Armed) => enforce(link.as_ref(), true),
        (Mode::Armed, _) => clear(),
        _ => Ok(()),
    };
    if let Err(error) = applied {
        atomic_write(MODE, old.name().as_bytes())?;
        if old == Mode::Armed {
            enforce(link.as_ref(), true).context("Could not restore the armed kill switch")?;
        } else {
            clear().context("Could not undo incomplete activation")?;
        }
        return Err(error);
    }
    Ok(())
}

pub fn restore() -> Result<()> {
    let _lock = lock()?;
    match fs::remove_file(CONTEXT) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    if Mode::load()? == Mode::Armed {
        enforce(None, !std::path::Path::new(TOKEN).exists())?;
    } else if std::path::Path::new(TOKEN).exists() {
        clear()?;
    }
    Ok(())
}

pub fn serve(mut peer: UnixStream) -> Result<()> {
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut command = String::new();
    BufReader::new(&peer).take(32).read_line(&mut command)?;
    let reply = match change(command.trim()) {
        Ok(()) => "ok".to_owned(),
        Err(e) => format!("{e:#}"),
    };
    peer.write_all(reply.as_bytes())?;
    Ok(())
}

pub fn request(action: &str) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return change(action);
    }
    let mut peer = UnixStream::connect(SOCKET)?;
    peer.set_read_timeout(Some(Duration::from_secs(8)))?;
    writeln!(peer, "{action}")?;
    let mut response = String::new();
    peer.take(4096).read_to_string(&mut response)?;
    ensure!(response == "ok", "{}", response.trim());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_pause_preserves_preference_and_next_connect_rearms() {
        let enabled = Mode::Off.next("enable-active").unwrap();
        assert!(enabled == Mode::Armed);
        let paused = enabled.next("pause").unwrap();
        assert!(paused == Mode::Standby);
        assert!(paused.next("arm").unwrap() == Mode::Armed);
        assert!(paused.next("disable").unwrap().next("arm").unwrap() == Mode::Off);
    }
}
