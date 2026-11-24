use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    net::IpAddr,
    os::fd::AsRawFd,
    process::{Command, Output},
};

struct ScopedRoute {
    family: &'static str,
    interface: String,
    gateway: String,
}

fn route(args: &[&str]) -> Result<Output> {
    Ok(Command::new("/sbin/route")
        .arg("-n")
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()?)
}

fn field<'a>(info: &'a str, name: &str) -> Option<&'a str> {
    info.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then_some(value.trim())
    })
}

impl ScopedRoute {
    fn info(family: &str, interface: &str, destination: &str) -> Result<String> {
        let out = route(&["get", family, "-ifscope", interface, destination])?;
        Ok(String::from_utf8(out.stdout)?)
    }

    fn marked(&self, info: &str) -> bool {
        let flags = field(info, "flags").unwrap_or("").trim_matches(['<', '>']);
        field(info, "interface") == Some(&self.interface)
            && field(info, "gateway") == Some(&self.gateway)
            && ["IFSCOPE", "PROTO2"]
                .iter()
                .all(|flag| flags.split(',').any(|f| f == *flag))
    }

    fn acquire(family: &'static str, interface: &str, target: &str) -> Result<Option<Self>> {
        let info = Self::info(family, interface, "default")?;
        if field(&info, "interface") != Some(interface) {
            return Ok(None);
        }
        let Some(gateway) = field(&info, "gateway") else {
            return Ok(None);
        };
        let (ip, scope) = gateway
            .split_once('%')
            .map_or((gateway, None), |(ip, scope)| (ip, Some(scope)));
        let ip: IpAddr = ip.parse().context("Invalid Wi-Fi gateway")?;
        ensure!(
            ip.is_ipv4() == (family == "-inet") && scope.is_none_or(|s| s == interface),
            "Invalid gateway scope"
        );
        let entry = Self {
            family,
            interface: interface.into(),
            gateway: gateway.into(),
        };
        if entry.marked(&info) {
            return Ok(Some(entry));
        }
        if field(&Self::info(family, interface, target)?, "interface") == Some(interface) {
            return Ok(None);
        }
        let out = route(&[
            "add", family, "-ifscope", interface, "-proto2", "default", gateway,
        ])?;
        ensure!(
            out.status.success() && entry.marked(&Self::info(family, interface, "default")?),
            "Cannot create Wi-Fi sign-in route"
        );
        Ok(Some(entry))
    }
}

pub struct PortalRoutes {
    owned: Vec<ScopedRoute>,
    _lock: File,
}

impl PortalRoutes {
    pub fn open(interface: &str) -> Result<Self> {
        let lock = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open("/var/run/io.github.ljste.openwarp.portal-lock")?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "A Wi-Fi sign-in session is already open."
        );
        let mut lease = Self {
            owned: Vec::new(),
            _lock: lock,
        };
        for (family, target) in [("-inet", "192.0.2.1"), ("-inet6", "2001:db8::1")] {
            if let Some(entry) = ScopedRoute::acquire(family, interface, target)? {
                lease.owned.push(entry);
            }
        }
        Ok(lease)
    }
}

impl Drop for PortalRoutes {
    fn drop(&mut self) {
        for r in &self.owned {
            if ScopedRoute::info(r.family, &r.interface, "default")
                .is_ok_and(|info| r.marked(&info))
            {
                let _ = route(&[
                    "delete",
                    r.family,
                    "-ifscope",
                    &r.interface,
                    "default",
                    &r.gateway,
                ]);
            }
        }
    }
}
