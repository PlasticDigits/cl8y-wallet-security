use super::*;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bech32::ToBase32;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use uuid::Uuid;
fn wallet() -> (SigningKey, String, String) {
    let k = SigningKey::random(&mut rand::rngs::OsRng);
    let pk = k.verifying_key().to_encoded_point(true);
    let a = bech32::encode(
        "terra",
        Ripemd160::digest(Sha256::digest(pk.as_bytes())).to_base32(),
        bech32::Variant::Bech32,
    )
    .unwrap();
    let p = STANDARD.encode(pk.as_bytes());
    (k, a, p)
}
fn sign(k: &SigningKey, a: &str, m: &str) -> String {
    let doc = json!({"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":STANDARD.encode(m),"signer":a}}],"sequence":"0"});
    let s: Signature = k.sign(doc.to_string().as_bytes());
    STANDARD.encode(s.to_bytes())
}
async fn proof(
    app: &App,
    headers: &HeaderMap,
    k: &SigningKey,
    a: &str,
    pk: &str,
    purpose: &str,
) -> auth::VerifyInput {
    let p: auth::ChallengeInput =
        serde_json::from_value(json!({"address":a,"purpose":purpose})).unwrap();
    let Json(c) = auth::challenge(
        State(app.clone()),
        ConnectInfo("192.0.2.1:1234".parse().unwrap()),
        headers.clone(),
        Json(p),
    )
    .await
    .unwrap_or_else(|_| panic!("challenge failed"));
    serde_json::from_value(
        json!({"id":c["id"],"public_key":pk,"signature":sign(k,a,c["message"].as_str().unwrap())}),
    )
    .unwrap()
}
#[tokio::test]
async fn postgres_replay_consent_outbox_concurrency() {
    let Ok(url) = env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL absent: PostgreSQL integration check skipped");
        return;
    };
    let db = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect(&url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let app = App {
        db,
        origin: "https://security.example".into(),
        chain_id: "columbus-5".into(),
        source_sha: "test".into(),
        contact_key: Arc::new([7; 32]),
        admission: Arc::new(admission::Admission::default()),
        trusted_proxies: Arc::new(Default::default()),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "origin",
        HeaderValue::from_static("https://security.example"),
    );
    let (key, address, pk) = wallet();
    let input = proof(&app, &headers, &key, &address, &pk, "login").await;
    let replay_id = input.id;
    let (cookies, Json(login)) = auth::verify(State(app.clone()), headers.clone(), Json(input))
        .await
        .unwrap_or_else(|_| panic!("login failed"));
    let replay: auth::VerifyInput =
        serde_json::from_value(json!({"id":replay_id,"public_key":pk,"signature":"invalid"}))
            .unwrap();
    assert!(
        auth::verify(State(app.clone()), headers.clone(), Json(replay))
            .await
            .is_err()
    );
    headers.insert(
        "cookie",
        cookies["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .parse()
            .unwrap(),
    );
    headers.insert(
        "x-csrf-token",
        login["csrf_token"].as_str().unwrap().parse().unwrap(),
    );
    let session = auth::authorized(&app, &headers)
        .await
        .unwrap_or_else(|_| panic!("session failed"));
    let mut forged = headers.clone();
    forged.insert("origin", HeaderValue::from_static("https://evil.example"));
    assert!(auth::authorized(&app, &forged).await.is_err());
    forged = headers.clone();
    forged.remove("x-csrf-token");
    assert!(auth::authorized(&app, &forged).await.is_err());
    // Eight held transaction connections previously exhausted the pool during session checks.
    let mut inputs = Vec::new();
    for _ in 0..8 {
        let (k, a, p) = wallet();
        inputs.push(proof(&app, &headers, &k, &a, &p, "add_wallet").await);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for input in inputs {
        let a = app.clone();
        let h = headers.clone();
        tasks.spawn(async move { auth::verify(State(a), h, Json(input)).await.is_ok() });
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(r) = tasks.join_next().await {
            assert!(r.unwrap())
        }
    })
    .await
    .expect("concurrent proofs must not deadlock");
    let (k, candidate, p) = wallet();
    let proposal: assignments::Proposal =
        serde_json::from_value(json!({"candidate_wallet":candidate,"role":"guardian"})).unwrap();
    let Json(created) = assignments::propose(State(app.clone()), headers.clone(), Json(proposal))
        .await
        .unwrap_or_else(|_| panic!("proposal failed"));
    let id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    assert_eq!(
        assignments::list(&app, session.profile_id).await.unwrap()[0]["status"],
        "awaiting_consent"
    );
    let consent = proof(
        &app,
        &headers,
        &k,
        &candidate,
        &p,
        &format!("assignment:{id}"),
    )
    .await;
    let _ = auth::verify(State(app.clone()), headers.clone(), Json(consent))
        .await
        .unwrap_or_else(|_| panic!("consent failed"));
    assert_eq!(
        assignments::list(&app, session.profile_id).await.unwrap()[0]["status"],
        "pending"
    );
    // Old delay snapshot wins over changed current profile delay when active removal starts.
    sqlx::query("UPDATE assignments SET executable_at=now()-interval '1 second',delay_seconds=172800 WHERE id=$1").bind(id).execute(&app.db).await.unwrap();
    let contact = Uuid::new_v4();
    let encrypted = notifications::encrypt(&app, "owned@example.test").unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("example"));
    let mut tampered = encrypted.clone();
    tampered[15] ^= 1;
    assert!(notifications::decrypt(&app, &tampered).is_err());
    sqlx::query("INSERT INTO contacts(id,profile_id,kind,encrypted_destination,verified_at,activation_at,consent_at) VALUES($1,$2,'email',$3,now(),now(),now())").bind(contact).bind(session.profile_id).bind(encrypted).execute(&app.db).await.unwrap();
    let _ = assignments::cancel(State(app.clone()), headers.clone(), Path(id))
        .await
        .unwrap_or_else(|_| panic!("cancel failed"));
    let seconds: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM removal_at-now())::float8 FROM assignments WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(seconds > 172790.0);
    let _ = assignments::cancel(State(app.clone()), headers.clone(), Path(id))
        .await
        .unwrap_or_else(|_| panic!("repeated cancel failed"));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE contact_id=$1")
            .bind(contact)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let _ = notifications::remove(State(app.clone()), headers.clone(), Path(contact))
        .await
        .unwrap_or_else(|_| panic!("contact removal failed"));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE contact_id=$1")
            .bind(contact)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(count, 2, "old contact must receive its own removal warning");
    // With absent providers, warnings remain durable and visible without a real send.
    worker::tick(&app).await.unwrap();
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE contact_id=$1 AND state='blocked' AND attempts=0").bind(contact).fetch_one(&app.db).await.unwrap();
    assert_eq!(count, 2);
    // Cross-profile destination verification cooldown and global quota are durable.
    let mut tx = app.db.begin().await.unwrap();
    let destination = format!("owned-{}@example.test", Uuid::new_v4());
    assert!(
        notifications::verification_budget(&app, &mut tx, &destination)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let mut tx = app.db.begin().await.unwrap();
    assert!(
        !notifications::verification_budget(&app, &mut tx, &destination.to_uppercase())
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    // Expired Telegram sends are never eligible for automatic reclaim, including mid-loop.
    let telegram = Uuid::new_v4();
    sqlx::query("INSERT INTO contacts(id,profile_id,kind,encrypted_destination,verified_at) VALUES($1,$2,'telegram',$3,now())").bind(telegram).bind(session.profile_id).bind(notifications::encrypt(&app,"owned-test-chat").unwrap()).execute(&app.db).await.unwrap();
    let event = format!("lease-fixture:{}", Uuid::new_v4());
    let mut tx = app.db.begin().await.unwrap();
    notifications::record(
        &mut tx,
        &event,
        session.profile_id,
        "test_timer",
        &address,
        chrono::Utc::now(),
        chrono::Utc::now() + chrono::Duration::hours(24),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE notification_outbox o SET state='sending',first_attempt_at=now(),delivery_transport=CASE WHEN c.kind='email' THEN 'resend' ELSE 'telegram' END,locked_until=now()-interval '1 second' FROM contacts c WHERE c.id=o.contact_id AND o.event_id=$1").bind(&event).execute(&app.db).await.unwrap();
    let lease = Uuid::new_v4();
    let claim = worker::claim(&app, lease).await.unwrap().unwrap();
    assert_ne!(claim.get::<Uuid, _>("contact_id"), telegram);
    let item: Uuid = claim.get("id");
    sqlx::query(
        "UPDATE notification_outbox SET locked_until=now()-interval '1 second' WHERE id=$1",
    )
    .bind(item)
    .execute(&app.db)
    .await
    .unwrap();
    let new_lease = Uuid::new_v4();
    let reclaimed = worker::claim(&app, new_lease).await.unwrap().unwrap();
    assert_eq!(reclaimed.get::<Uuid, _>("id"), item);
    assert_eq!(sqlx::query("UPDATE notification_outbox SET state='sent' WHERE id=$1 AND lease_id=$2 AND state='sending'").bind(item).bind(lease).execute(&app.db).await.unwrap().rows_affected(),0,"stale owner cannot acknowledge a reclaimed item");
    // SMTP remains non-reclaimable even if the process/provider configuration changes.
    sqlx::query("UPDATE notification_outbox SET delivery_transport='smtp',locked_until=now()-interval '1 second' WHERE id=$1").bind(item).execute(&app.db).await.unwrap();
    assert!(worker::claim(&app, Uuid::new_v4()).await.unwrap().is_none());
    worker::tick(&app).await.unwrap();
    let outcome = sqlx::query("SELECT state,last_error_code FROM notification_outbox WHERE id=$1")
        .bind(item)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(outcome.get::<String, _>("state"), "failed");
    assert_eq!(
        outcome.get::<String, _>("last_error_code"),
        "delivery_uncertain"
    );
    // An ambiguous Resend attempt must never outlive its deduplication window,
    // including pending/blocked rows across provider switches and process downtime.
    for state in ["pending", "blocked"] {
        sqlx::query("INSERT INTO notification_outbox(id,event_id,contact_id,template,state,attempts,delivery_transport,first_attempt_at,created_at) VALUES($1,$2,$3,$4,$5,1,'resend',now()-interval '25 hours',now()-interval '2 days')")
            .bind(Uuid::new_v4()).bind(&event).bind(contact).bind(format!("aged-{state}")).bind(state).execute(&app.db).await.unwrap();
    }
    env::set_var("EMAIL_PROVIDER", "smtp");
    env::set_var("MAILU_SMTP_TOKEN", "synthetic-owned-only");
    env::set_var("MAILU_DELIVERY_ENABLED", "false");
    assert!(
        notifications::email_transport().is_none(),
        "SMTP credential alone cannot activate delivery"
    );
    env::set_var("MAILU_DELIVERY_ENABLED", "true");
    env::set_var("NOTIFICATION_SANDBOX_DESTINATIONS", "");
    assert!(worker::claim(&app, Uuid::new_v4()).await.unwrap().is_none());
    worker::tick(&app).await.unwrap();
    env::set_var("EMAIL_PROVIDER", "resend");
    env::set_var("RESEND_API_KEY", "synthetic-owned-only");
    env::set_var("MAIL_FROM", "owned@example.test");
    assert!(worker::claim(&app, Uuid::new_v4()).await.unwrap().is_none());
    let expired:i64=sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE event_id=$1 AND template IN ('aged-pending','aged-blocked') AND state='failed' AND last_error_code='delivery_uncertain'")
        .bind(&event).fetch_one(&app.db).await.unwrap();
    assert_eq!(expired, 2);
    // An old item blocked before any send gets a fresh first-attempt window.
    let first = Uuid::new_v4();
    sqlx::query("INSERT INTO notification_outbox(id,event_id,contact_id,template,state,attempts,created_at) VALUES($1,$2,$3,'never-attempted','blocked',0,now()-interval '2 days')")
        .bind(first).bind(&event).bind(contact).execute(&app.db).await.unwrap();
    let fresh = worker::claim(&app, Uuid::new_v4()).await.unwrap().unwrap();
    assert_eq!(fresh.get::<Uuid, _>("id"), first);
    assert_eq!(fresh.get::<String, _>("delivery_transport"), "resend");
    assert!(
        fresh.get::<chrono::DateTime<chrono::Utc>, _>("first_attempt_at")
            > chrono::Utc::now() - chrono::Duration::seconds(5)
    );
    // A known sandbox rejection consumes no actual attempt and clears provisional
    // transport/window selection so an initial send can use a later provider.
    sqlx::query("UPDATE notification_outbox SET state='pending',attempts=0,delivery_transport=NULL,first_attempt_at=NULL WHERE id=$1")
        .bind(first).execute(&app.db).await.unwrap();
    worker::tick(&app).await.unwrap();
    let fresh=sqlx::query("SELECT state,attempts,delivery_transport,first_attempt_at FROM notification_outbox WHERE id=$1").bind(first).fetch_one(&app.db).await.unwrap();
    assert_eq!(fresh.get::<String, _>("state"), "blocked");
    assert_eq!(fresh.get::<i32, _>("attempts"), 0);
    assert!(fresh
        .get::<Option<String>, _>("delivery_transport")
        .is_none());
    assert!(fresh
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("first_attempt_at")
        .is_none());
    for name in [
        "EMAIL_PROVIDER",
        "MAILU_SMTP_TOKEN",
        "MAILU_DELIVERY_ENABLED",
        "NOTIFICATION_SANDBOX_DESTINATIONS",
        "RESEND_API_KEY",
        "MAIL_FROM",
    ] {
        env::remove_var(name);
    }
    chain::fixture_ingestion(&app, &address).await.unwrap();
}
