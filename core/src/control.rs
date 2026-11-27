use crate::network::ready;
use anyhow::{Result, bail};
use std::{
    io::Read,
    os::fd::{AsRawFd, RawFd},
    os::unix::net::UnixStream,
    time::Duration,
};

pub struct Control<'a> {
    peer: Option<&'a UnixStream>,
    pub p2p: bool,
}

impl<'a> Control<'a> {
    pub fn new(peer: Option<&'a UnixStream>) -> Self {
        Self { peer, p2p: false }
    }

    pub fn wait(&mut self, sockets: &[RawFd], timeout: Duration) -> Result<Option<[bool; 3]>> {
        let mut fds = [-1; 3];
        fds[..sockets.len()].copy_from_slice(sockets);
        fds[sockets.len()] = self.peer.map_or(-1, AsRawFd::as_raw_fd);
        let events = ready(&fds, timeout)?;
        if let Some(mut peer) = self.peer.filter(|_| events[sockets.len()]) {
            let mut commands = [0; 64];
            let count = peer.read(&mut commands)?;
            if count == 0 {
                return Ok(None);
            }
            for command in &commands[..count] {
                self.p2p = match command {
                    b'1' => true,
                    b'0' => false,
                    _ => bail!("Unknown tunnel control command"),
                };
            }
        }
        Ok(Some(events))
    }
}

#[cfg(test)]
mod tests {
    use super::Control;
    use std::{io::Write, os::unix::net::UnixStream, time::Duration};

    #[test]
    fn mode_updates_preserve_the_session_and_eof_ends_it() {
        let (mut app, helper) = UnixStream::pair().unwrap();
        let mut control = Control::new(Some(&helper));
        assert!(!control.p2p);
        for (commands, expected) in [("1", true), ("010", false)] {
            app.write_all(commands.as_bytes()).unwrap();
            assert!(control.wait(&[], Duration::ZERO).unwrap().is_some());
            assert_eq!(control.p2p, expected);
        }
        drop(app);
        assert!(control.wait(&[], Duration::ZERO).unwrap().is_none());
    }
}
