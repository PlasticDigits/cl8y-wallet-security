use sha2::{Digest, Sha256};
use std::{
    env,
    fs::File,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
const BIND: &str = "10.8.0.1:18188";
const MAX_BYTES: u64 = 270 * 1024 * 1024;
struct Snapshot {
    path: String,
    size: u64,
    device: u64,
    inode: u64,
    modified: std::time::SystemTime,
}
fn open_fixed(path: &str) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}
impl Snapshot {
    fn open(&self) -> Option<File> {
        let file = open_fixed(&self.path).ok()?;
        let meta = file.metadata().ok()?;
        if !meta.is_file()
            || meta.len() != self.size
            || meta.dev() != self.device
            || meta.ino() != self.inode
            || meta.modified().ok()? != self.modified
        {
            return None;
        }
        Some(file)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn capability_deadline(
    expires: u64,
    wall: u64,
    start: Instant,
) -> Result<Instant, Box<dyn std::error::Error>> {
    let lifetime = expires
        .checked_sub(wall)
        .ok_or("expired export capability")?;
    if lifetime == 0 || lifetime > 600 {
        return Err("export capability lifetime invalid".into());
    }
    Ok(start + Duration::from_secs(lifetime))
}
fn live(expires: u64, wall: u64, deadline: Instant, mono: Instant) -> bool {
    wall < expires && mono < deadline
}
fn hash_cipher(
    file: &mut File,
    size: u64,
    expires: u64,
    deadline: Instant,
) -> Result<String, Box<dyn std::error::Error>> {
    if size < 22 || size > MAX_BYTES {
        return Err("cipher size invalid".into());
    }
    if !live(expires, now(), deadline, Instant::now()) {
        return Err("cipher validation deadline".into());
    }
    let mut magic = [0u8; 22];
    file.read_exact(&mut magic)?;
    if &magic != b"age-encryption.org/v1\n" {
        return Err("cipher envelope missing".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(magic);
    let mut buffer = [0u8; 65536];
    let mut remaining = size - 22;
    while remaining > 0 {
        if !live(expires, now(), deadline, Instant::now()) {
            return Err("cipher validation deadline".into());
        }
        let amount = remaining.min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..amount])?;
        if count == 0 {
            return Err("cipher truncated while validating".into());
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if !live(expires, now(), deadline, Instant::now()) {
        return Err("cipher validation deadline".into());
    }
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err("cipher grew while validating".into());
    }
    Ok(format!("{:x}", hasher.finalize()))
}
fn valid_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn write_bounded(
    stream: &mut TcpStream,
    mut data: &[u8],
    deadline: Instant,
    expires: u64,
) -> std::io::Result<()> {
    while !data.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || now() >= expires {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        stream.set_write_timeout(Some(remaining.min(Duration::from_secs(1))))?;
        match stream.write(data) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => data = &data[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn response(stream: &mut TcpStream, status: &str, deadline: Instant, expires: u64) {
    let bytes=format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    let _ = write_bounded(stream, bytes.as_bytes(), deadline, expires);
}
fn authorized(header: &str, token: &[u8]) -> bool {
    let mut auth = None;
    for line in header.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return false;
        }
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        if key.eq_ignore_ascii_case("authorization") {
            if auth.is_some() {
                return false;
            }
            auth = value.trim().strip_prefix("Bearer ");
            if auth.is_none() {
                return false;
            }
        }
    }
    let Some(value) = auth else { return false };
    value.len() == token.len() && bool::from(value.as_bytes().ct_eq(token))
}
fn serve(
    mut stream: TcpStream,
    peer: SocketAddr,
    token: Arc<Vec<u8>>,
    snapshot: Arc<Snapshot>,
    expires: u64,
    global_deadline: Instant,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let deadline = (Instant::now() + Duration::from_secs(120)).min(global_deadline);
    let header_deadline = (Instant::now() + Duration::from_secs(5)).min(deadline);
    let mut bytes = Vec::with_capacity(1024);
    while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
        let budget = header_deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() || now() >= expires {
            return;
        }
        if stream
            .set_read_timeout(Some(budget.min(Duration::from_secs(1))))
            .is_err()
        {
            return;
        }
        let mut byte = [0u8];
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        bytes.push(byte[0]);
    }
    if !bytes.ends_with(b"\r\n\r\n") {
        response(
            &mut stream,
            "431 Request Header Fields Too Large",
            deadline,
            expires,
        );
        return;
    }
    let Ok(header) = std::str::from_utf8(&bytes) else {
        response(&mut stream, "400 Bad Request", deadline, expires);
        return;
    };
    let line = header.split("\r\n").next().unwrap_or("");
    if line == "GET /healthz HTTP/1.1" && peer.ip() == IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)) {
        response(
            &mut stream,
            if now() < expires {
                "200 OK"
            } else {
                "503 Service Unavailable"
            },
            deadline,
            expires,
        );
        return;
    }
    if now() >= expires
        || peer.ip() != IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))
        || !authorized(header, &token)
    {
        response(&mut stream, "403 Forbidden", deadline, expires);
        return;
    }
    if line != "GET /cipher HTTP/1.1" && line != "HEAD /cipher HTTP/1.1" {
        response(&mut stream, "404 Not Found", deadline, expires);
        return;
    }
    let Some(mut file) = snapshot.open() else {
        response(&mut stream, "409 Conflict", deadline, expires);
        return;
    };
    let size = snapshot.size;
    let headers=format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    if write_bounded(&mut stream, headers.as_bytes(), deadline, expires).is_err() {
        return;
    }
    if line.starts_with("HEAD ") {
        return;
    }
    let mut buffer = [0u8; 65536];
    let mut remaining = size;
    while remaining > 0 {
        if Instant::now() > deadline || now() >= expires {
            return;
        }
        let amount = remaining.min(buffer.len() as u64) as usize;
        let Ok(count) = file.read(&mut buffer[..amount]) else {
            return;
        };
        if count == 0 {
            return;
        }
        if write_bounded(&mut stream, &buffer[..count], deadline, expires).is_err() {
            return;
        }
        remaining -= count as u64;
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().nth(1).as_deref() == Some("--healthcheck") {
        let mut stream = TcpStream::connect_timeout(&BIND.parse()?, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: private\r\nConnection: close\r\n\r\n")?;
        let mut result = [0u8; 15];
        stream.read_exact(&mut result)?;
        return if &result == b"HTTP/1.1 200 OK" {
            Ok(())
        } else {
            Err("private exporter not ready".into())
        };
    }
    let token = env::var("EXPORT_TOKEN")?;
    if !valid_hex(&token) {
        return Err("invalid scoped export capability".into());
    }
    let expected = env::var("EXPECTED_CIPHER_SHA256")?;
    if !valid_hex(&expected) {
        return Err("invalid cipher digest".into());
    }
    let expires: u64 = env::var("EXPORT_EXPIRES_UNIX")?.parse()?;
    let hard_deadline = capability_deadline(expires, now(), Instant::now())?;
    let startup_deadline = (Instant::now() + Duration::from_secs(30)).min(hard_deadline);
    let filename = env::var("EXPORT_FILENAME")?;
    let prefix = "wallet-security-";
    let suffix = ".dump.age";
    let Some(stamp) = filename
        .strip_prefix(prefix)
        .and_then(|v| v.strip_suffix(suffix))
    else {
        return Err("invalid owned cipher filename".into());
    };
    if stamp.len() != 16
        || !stamp.bytes().enumerate().all(|(i, c)| {
            if i == 8 {
                c == b'T'
            } else if i == 15 {
                c == b'Z'
            } else {
                c.is_ascii_digit()
            }
        })
    {
        return Err("invalid owned cipher filename".into());
    }
    let path = format!("/export/{filename}");
    let mut file = open_fixed(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err("not a regular cipher".into());
    }
    let size = meta.len();
    if size == 0 || size > MAX_BYTES {
        return Err("cipher size invalid".into());
    }
    if hash_cipher(&mut file, size, expires, startup_deadline)? != expected {
        return Err("cipher digest differs".into());
    }
    let after = file.metadata()?;
    if meta.len() != after.len() || meta.modified()? != after.modified()? {
        return Err("cipher changed while validating".into());
    }
    let snapshot = Arc::new(Snapshot {
        path,
        size,
        device: meta.dev(),
        inode: meta.ino(),
        modified: meta.modified()?,
    });
    if Instant::now() >= hard_deadline || now() >= expires {
        return Err("export capability expired before bind".into());
    }
    let listener = TcpListener::bind(BIND)?;
    listener.set_nonblocking(true)?;
    let token = Arc::new(token.into_bytes());
    let active = Arc::new(AtomicUsize::new(0));
    println!("private_cipher_export_ready bind=10.8.0.1:18188 client=10.8.0.2 cipher_only=true");
    while now() < expires && Instant::now() < hard_deadline {
        match listener.accept() {
            Ok((stream, peer)) => {
                if active.load(Ordering::SeqCst) >= 2 {
                    drop(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let token = token.clone();
                let snapshot = snapshot.clone();
                let count = active.clone();
                std::thread::spawn(move || {
                    serve(stream, peer, token, snapshot, expires, hard_deadline);
                    count.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(_) => return Err("private listener failed".into()),
        }
    }
    println!("private_cipher_export_expired");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_header_only() {
        let token = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(authorized("GET /cipher HTTP/1.1\r\nAuthorization: Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",token));
        assert!(!authorized(
            "GET /cipher?token=aaaaaaaa HTTP/1.1\r\n\r\n",
            token
        ));
        assert!(!authorized(
            "GET /cipher HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n",
            token
        ));
        assert!(!authorized("GET /cipher HTTP/1.1\r\nAuthorization: Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nAuthorization: Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",token));
    }
    #[test]
    fn exact_capability_shape() {
        assert!(valid_hex(&"a".repeat(64)));
        assert!(!valid_hex(&"g".repeat(64)));
        assert!(!valid_hex(&"a".repeat(63)));
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    fn fixture() -> (std::path::PathBuf, Arc<Snapshot>, Vec<u8>) {
        let path = env::temp_dir().join(format!(
            "wallet-security-cipher-fixture-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data = b"age-encryption.org/v1\nowned-cipher-test-only".to_vec();
        std::fs::write(&path, &data).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let snap = Arc::new(Snapshot {
            path: path.to_string_lossy().into(),
            size: meta.len(),
            device: meta.dev(),
            inode: meta.ino(),
            modified: meta.modified().unwrap(),
        });
        (path, snap, data)
    }
    fn request(snap: Arc<Snapshot>, peer: IpAddr, header: &str) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let token = Arc::new(vec![b'a'; 64]);
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(
                stream,
                SocketAddr::new(peer, 12345),
                token,
                snap,
                now() + 30,
                Instant::now() + Duration::from_secs(30),
            );
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(header.as_bytes()).unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).unwrap();
        thread.join().unwrap();
        out
    }
    fn good() -> String {
        format!(
            "GET /cipher HTTP/1.1\r\nHost: private\r\nAuthorization: Bearer {}\r\n\r\n",
            "a".repeat(64)
        )
    }
    #[test]
    fn actual_fixed_body_only_for_peer_and_header() {
        let (path, snap, data) = fixture();
        let out = request(snap.clone(), "10.8.0.2".parse().unwrap(), &good());
        assert!(out.starts_with(b"HTTP/1.1 200 OK"));
        assert!(out.ends_with(&data));
        let out = request(snap.clone(), "10.8.0.3".parse().unwrap(), &good());
        assert!(out.starts_with(b"HTTP/1.1 403"));
        let out = request(
            snap,
            "10.8.0.2".parse().unwrap(),
            "GET /cipher?token=ignored HTTP/1.1\r\nHost: private\r\n\r\n",
        );
        assert!(out.starts_with(b"HTTP/1.1 403"));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn mutation_and_symlink_fail_closed() {
        let (path, snap, _) = fixture();
        std::fs::write(&path, b"changed").unwrap();
        let out = request(snap, "10.8.0.2".parse().unwrap(), &good());
        assert!(out.starts_with(b"HTTP/1.1 409"));
        let link = path.with_extension("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(open_fixed(link.to_str().unwrap()).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[test]
    fn nonreading_peer_cannot_reset_write_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let started = Instant::now();
            let data = vec![42u8; 8 * 1024 * 1024];
            let result = write_bounded(
                &mut stream,
                &data,
                started + Duration::from_millis(80),
                now() + 30,
            );
            assert!(result.is_err());
            assert!(started.elapsed() < Duration::from_secs(1));
        });
        let _client = TcpStream::connect(addr).unwrap();
        thread.join().unwrap();
    }
}

#[cfg(test)]
mod startup_bound_tests {
    use super::*;
    #[test]
    fn expired_and_rollback_cannot_extend_cap() {
        let start = Instant::now();
        assert!(capability_deadline(100, 100, start).is_err());
        assert!(capability_deadline(701, 100, start).is_err());
        let cap = capability_deadline(200, 100, start).unwrap();
        assert!(!live(200, 1, cap, cap + Duration::from_nanos(1)));
        assert!(!live(200, 201, cap, start));
    }
    #[test]
    fn declared_size_and_startup_expiry_are_enforced() {
        let path = env::temp_dir().join(format!("wallet-export-growth-{}", now()));
        let data = b"age-encryption.org/v1\nowned-growth-case";
        std::fs::write(&path, data).unwrap();
        let mut file = open_fixed(path.to_str().unwrap()).unwrap();
        assert!(hash_cipher(
            &mut file,
            data.len() as u64 - 1,
            now() + 30,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
        let mut file = open_fixed(path.to_str().unwrap()).unwrap();
        assert!(hash_cipher(
            &mut file,
            data.len() as u64,
            0,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
        std::fs::remove_file(path).unwrap();
    }
}
