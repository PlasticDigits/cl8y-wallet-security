//! Credential-free, fixed-target TCP relay. No URL, destination or token inputs.
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
const BACKEND: &str = "149.154.166.110:443";
const LISTEN: &str = "0.0.0.0:443";
const MAX_CONNECTIONS: usize = 4;
const SESSION: Duration = Duration::from_secs(25);

struct Permit(Arc<AtomicUsize>);
impl Permit {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_CONNECTIONS).then_some(n + 1)
            })
            .ok()?;
        Some(Self(active.clone()))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
fn copy_until(mut source: TcpStream, mut target: TcpStream, deadline: Instant) {
    let mut buffer = [0u8; 8192];
    while Instant::now() < deadline {
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => {
                let mut offset = 0;
                while offset < size && Instant::now() < deadline {
                    match target.write(&buffer[offset..size]) {
                        Ok(0) => return,
                        Ok(n) => offset += n,
                        Err(e)
                            if [
                                io::ErrorKind::WouldBlock,
                                io::ErrorKind::TimedOut,
                                io::ErrorKind::Interrupted,
                            ]
                            .contains(&e.kind()) => {}
                        Err(_) => return,
                    }
                }
            }
            Err(e)
                if [
                    io::ErrorKind::WouldBlock,
                    io::ErrorKind::TimedOut,
                    io::ErrorKind::Interrupted,
                ]
                .contains(&e.kind()) => {}
            Err(_) => break,
        }
    }
    // Half-close on EOF, but close both directions when the absolute bound expires.
    let _ = target.shutdown(if Instant::now() >= deadline {
        Shutdown::Both
    } else {
        Shutdown::Write
    });
}
fn relay(incoming: TcpStream, backend: SocketAddr, session: Duration) {
    let deadline = Instant::now() + session;
    let Ok(upstream) = TcpStream::connect_timeout(&backend, Duration::from_secs(5).min(session))
    else {
        return;
    };
    for stream in [&incoming, &upstream] {
        if stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .is_err()
            || stream
                .set_write_timeout(Some(Duration::from_millis(100)))
                .is_err()
        {
            return;
        }
    }
    let (Ok(reverse_in), Ok(reverse_out)) = (upstream.try_clone(), incoming.try_clone()) else {
        return;
    };
    let reverse = thread::spawn(move || copy_until(reverse_in, reverse_out, deadline));
    copy_until(incoming, upstream, deadline);
    let _ = reverse.join();
}
fn main() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(io::Error::other("arguments_refused"));
    }
    let listener = TcpListener::bind(LISTEN)?;
    let active = Arc::new(AtomicUsize::new(0));
    let backend: SocketAddr = BACKEND.parse().expect("fixed address");
    for connection in listener.incoming() {
        let Ok(incoming) = connection else { continue };
        let Some(permit) = Permit::acquire(&active) else {
            drop(incoming);
            continue;
        };
        thread::spawn(move || {
            let _permit = permit;
            relay(incoming, backend, SESSION);
        });
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forwards_opaque_bytes_both_ways_and_bounds_idle_session() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend = upstream.local_addr().unwrap();
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(front.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (incoming, _) = front.accept().unwrap();
        let handle = thread::spawn(move || relay(incoming, backend, Duration::from_millis(300)));
        let (mut server, _) = upstream.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"synthetic opaque bytes\0\xff").unwrap();
        let mut bytes = [0u8; 24];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"synthetic opaque bytes\0\xff");
        server.write_all(b"250 fixture\r\n").unwrap();
        let mut response = [0u8; 13];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"250 fixture\r\n");
        let start = Instant::now();
        handle.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(client.read(&mut response).unwrap(), 0);
    }
    #[test]
    fn bounds_active_connections_and_releases_slots() {
        let active = Arc::new(AtomicUsize::new(0));
        let permits: Vec<_> = (0..4).map(|_| Permit::acquire(&active).unwrap()).collect();
        assert!(Permit::acquire(&active).is_none());
        drop(permits);
        assert!(Permit::acquire(&active).is_some());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
