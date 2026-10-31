use crate::{Error, Result};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
#[derive(Default)]
pub struct Admission {
    inner: Mutex<Limits>,
}
#[derive(Default)]
struct Limits {
    peers: HashMap<IpAddr, (Instant, u32)>,
    window: Option<Instant>,
    total: u32,
}
impl Admission {
    pub fn admit(&self, peer: IpAddr) -> Result<()> {
        let mut state = self.inner.lock().map_err(|_| Error::limited())?;
        let now = Instant::now();
        let window = Duration::from_secs(60);
        if state.window.is_none_or(|t| now.duration_since(t) >= window) {
            state.window = Some(now);
            state.total = 0;
            state
                .peers
                .retain(|_, (t, _)| now.duration_since(*t) < window);
        }
        if state.total >= 500 {
            return Err(Error::limited());
        }
        if state.peers.len() >= 4096 && !state.peers.contains_key(&peer) {
            return Err(Error::limited());
        }
        let entry = state.peers.entry(peer).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0)
        }
        if entry.1 >= 30 {
            return Err(Error::limited());
        }
        entry.1 += 1;
        state.total += 1;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attacker_cannot_spend_victim_peer_quota() {
        let a = Admission::default();
        let attacker = "192.0.2.1".parse().unwrap();
        let victim = "192.0.2.2".parse().unwrap();
        for _ in 0..30 {
            assert!(a.admit(attacker).is_ok())
        }
        assert!(a.admit(attacker).is_err());
        assert!(a.admit(victim).is_ok());
    }
    #[test]
    fn spoofed_many_wallets_bounded_by_actual_peer() {
        let a = Admission::default();
        let peer = "192.0.2.1".parse().unwrap();
        assert_eq!((0..1000).filter(|_| a.admit(peer).is_ok()).count(), 30);
    }
}
