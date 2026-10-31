//! Dedicated Mailu submission. Host, TLS identity and sender are not user configurable.
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use std::{env, time::Duration};

pub const HOST: &str = "mail.cl8y.com";
pub const SENDER: &str = "wallet-security-notices@cl8y.com";

pub fn ready() -> bool {
    env::var("MAILU_SMTP_TOKEN").is_ok_and(|v| !v.is_empty())
}

fn message(destination: &str, text: &str, id: &str) -> Result<Message, &'static str> {
    // Accept exactly one bare mailbox; no display names, lists or header injection.
    if destination
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("provider_rejected");
    }
    let address = destination.parse().map_err(|_| "provider_rejected")?;
    let event = uuid::Uuid::parse_str(id).map_err(|_| "provider_rejected")?;
    Message::builder()
        .from(SENDER.parse().map_err(|_| "transport_configuration")?)
        .to(Mailbox::new(None, address))
        .subject("CL8Y wallet security notice")
        .message_id(Some(format!("<{event}@security.cl8y.com>")))
        .body(text.to_owned())
        .map_err(|_| "provider_rejected")
}

pub async fn deliver(destination: &str, text: &str, id: &str) -> Result<(), &'static str> {
    let mail = message(destination, text, id)?;
    let token = env::var("MAILU_SMTP_TOKEN")
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or("provider_unconfigured")?;
    // Required STARTTLS validates HOST against public roots before AUTH or message data.
    // Deployment routes HOST through a fixed TCP gateway on an internal network.
    let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(HOST)
        .map_err(|_| "transport_configuration")?
        .port(1587)
        .credentials(Credentials::new(SENDER.to_owned(), token))
        .timeout(Some(Duration::from_secs(10)))
        .build();
    send(transport, mail).await
}

async fn send(
    transport: AsyncSmtpTransport<Tokio1Executor>,
    mail: Message,
) -> Result<(), &'static str> {
    // Bound the whole exchange, not just each SMTP command. Never log provider errors.
    match tokio::time::timeout(Duration::from_secs(15), transport.send(mail)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) if e.is_permanent() => Err("provider_rejected"),
        // The pinned Tokio transport ignores QUIT failure after accepted DATA.
        // An explicit SMTP 4xx therefore proves rejection and can be retried.
        Ok(Err(e)) if e.is_transient() => Err("provider_temporary"),
        _ => Err("delivery_uncertain"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    async fn line<S: tokio::io::AsyncRead + Unpin>(io: &mut BufReader<S>) -> String {
        let mut line = String::new();
        io.read_line(&mut line).await.unwrap();
        line
    }

    // Synthetic loopback SMTP only. No production hostname resolution or credentials.
    async fn fixture(mode: &str) -> (Result<(), &'static str>, bool) {
        let signed = rcgen::generate_simple_self_signed(vec![HOST.into()]).unwrap();
        let cert = signed.cert.der().clone();
        let key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
            signed.key_pair.serialize_der(),
        );
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = mode.to_owned();
        let server_mode = mode.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut io = BufReader::new(stream);
            io.get_mut()
                .write_all(b"220 fixture ESMTP\r\n")
                .await
                .unwrap();
            assert!(line(&mut io).await.starts_with("EHLO "));
            io.get_mut()
                .write_all(b"250-fixture\r\n250 STARTTLS\r\n")
                .await
                .unwrap();
            assert_eq!(line(&mut io).await, "STARTTLS\r\n");
            if server_mode == "refuse" {
                io.get_mut()
                    .write_all(b"454 TLS unavailable\r\n")
                    .await
                    .unwrap();
                // Any subsequent AUTH, MAIL or RCPT would expose data before TLS.
                let after = line(&mut io).await;
                return after.is_empty() || after == "QUIT\r\n";
            }
            io.get_mut().write_all(b"220 start TLS\r\n").await.unwrap();
            let Ok(stream) = acceptor.accept(io.into_inner()).await else {
                return server_mode == "wrong-host";
            };
            let mut io = BufReader::new(stream);
            assert!(line(&mut io).await.starts_with("EHLO "));
            io.get_mut()
                .write_all(b"250-fixture\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            assert!(line(&mut io).await.starts_with("AUTH PLAIN "));
            io.get_mut()
                .write_all(b"235 authenticated\r\n")
                .await
                .unwrap();
            assert_eq!(line(&mut io).await, format!("MAIL FROM:<{SENDER}>\r\n"));
            io.get_mut().write_all(b"250 accepted\r\n").await.unwrap();
            assert_eq!(line(&mut io).await, "RCPT TO:<owned@example.test>\r\n");
            io.get_mut().write_all(b"250 accepted\r\n").await.unwrap();
            assert_eq!(line(&mut io).await, "DATA\r\n");
            io.get_mut().write_all(b"354 data\r\n").await.unwrap();
            while line(&mut io).await != ".\r\n" {}
            if server_mode == "quit4xx" {
                io.get_mut().write_all(b"250 accepted\r\n").await.unwrap();
                assert_eq!(line(&mut io).await, "QUIT\r\n");
                io.get_mut().write_all(b"454 closing\r\n").await.unwrap();
            }
            // Simulate acceptance with the final 250 response lost. No replay allowed.
            true
        });
        let tls = TlsParameters::builder(
            if mode == "wrong-host" {
                "wrong.example.test"
            } else {
                HOST
            }
            .into(),
        )
        .add_root_certificate(Certificate::from_der(cert.to_vec()).unwrap())
        .build()
        .unwrap();
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay("127.0.0.1")
            .unwrap()
            .port(port)
            .tls(Tls::Required(tls))
            .credentials(Credentials::new(
                SENDER.into(),
                "synthetic-test-only".into(),
            ))
            .timeout(Some(Duration::from_secs(2)))
            .build();
        let outcome = send(
            transport,
            message(
                "owned@example.test",
                "owned synthetic fixture",
                "8abdbeba-b7bb-4c7d-a3b5-8dc5a2fdc95a",
            )
            .unwrap(),
        )
        .await;
        (outcome, server.await.unwrap())
    }

    #[tokio::test]
    async fn required_starttls_hostname_and_ambiguous_data() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let (code, private) = fixture("refuse").await;
            assert_eq!(code, Err("provider_temporary"));
            assert!(private);
            let (code, private) = fixture("wrong-host").await;
            assert_eq!(code, Err("delivery_uncertain"));
            assert!(private);
            let (code, complete) = fixture("disconnect").await;
            assert_eq!(code, Err("delivery_uncertain"));
            assert!(complete);
            let (code, complete) = fixture("quit4xx").await;
            assert_eq!(code, Ok(()));
            assert!(complete);
        })
        .await
        .unwrap();
    }
    #[test]
    fn envelope_and_headers_are_fixed() {
        let id = "8abdbeba-b7bb-4c7d-a3b5-8dc5a2fdc95a";
        for invalid in [
            "a@example.test\r\nBcc: b@example.test",
            "a@example.test,b@example.test",
            "Name <a@example.test>",
        ] {
            assert!(message(invalid, "fixture", id).is_err());
        }
        assert!(message("owned@example.test", "fixture", "not-a-uuid").is_err());
        let m = message("owned@example.test", ".\r\nBcc: body only", id).unwrap();
        assert_eq!(m.envelope().from().unwrap().to_string(), SENDER);
        assert_eq!(m.envelope().to().len(), 1);
        assert!(String::from_utf8(m.formatted())
            .unwrap()
            .contains(&format!("Message-ID: <{id}@security.cl8y.com>")));
    }
}
