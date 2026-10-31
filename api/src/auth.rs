use crate::{App, Error, Result};
use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand::RngCore;
use ripemd::Ripemd160;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::net::SocketAddr;
use uuid::Uuid;

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
pub fn valid_address(address: &str) -> bool {
    bech32::decode(address)
        .map(|(hrp, data, variant)| {
            hrp == "terra"
                && variant == bech32::Variant::Bech32
                && <Vec<u8> as bech32::FromBase32>::from_base32(&data)
                    .map(|v| v.len() == 20)
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}
pub fn verify_signature(address: &str, message: &str, public_key: &str, signature: &str) -> bool {
    use bech32::ToBase32;
    let Ok(pk) = STANDARD.decode(public_key) else {
        return false;
    };
    if pk.len() != 33 {
        return false;
    }
    let Ok(key) = VerifyingKey::from_sec1_bytes(&pk) else {
        return false;
    };
    let derived = Ripemd160::digest(Sha256::digest(&pk));
    let Ok(derived) = bech32::encode("terra", derived.to_base32(), bech32::Variant::Bech32) else {
        return false;
    };
    if derived != address {
        return false;
    }
    let Ok(raw) = STANDARD.decode(signature) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&raw) else {
        return false;
    };
    // ADR-036 uses canonical sorted JSON, empty chain_id and account/sequence 0.
    // Actual chain and origin are bound inside the signed message.
    let doc = json!({"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":STANDARD.encode(message),"signer":address}}],"sequence":"0"});
    key.verify(doc.to_string().as_bytes(), &sig).is_ok()
}
#[derive(Clone)]
pub struct Session {
    pub profile_id: Uuid,
    pub csrf: String,
    pub anchor: String,
}
pub async fn session(app: &App, headers: &HeaderMap) -> Result<Session> {
    let token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|x| x.trim().strip_prefix("__Host-cw_session="))
        })
        .ok_or(Error::unauthorized())?;
    let row=sqlx::query("SELECT s.profile_id,s.csrf_token,p.anchor_wallet FROM sessions s JOIN profiles p ON p.id=s.profile_id WHERE token_hash=$1 AND expires_at>now()")
        .bind(hash(token)).fetch_optional(&app.db).await?.ok_or(Error::unauthorized())?;
    Ok(Session {
        profile_id: row.get("profile_id"),
        csrf: row.get("csrf_token"),
        anchor: row.get("anchor_wallet"),
    })
}
pub fn origin(app: &App, headers: &HeaderMap) -> Result<()> {
    if headers.get("origin").and_then(|v| v.to_str().ok()) != Some(app.origin.as_str()) {
        return Err(Error::forbidden());
    }
    Ok(())
}
pub fn csrf(s: &Session, headers: &HeaderMap) -> Result<()> {
    if headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(s.csrf.as_str()) {
        return Err(Error::forbidden());
    }
    Ok(())
}
pub async fn authorized(app: &App, headers: &HeaderMap) -> Result<Session> {
    origin(app, headers)?;
    let s = session(app, headers).await?;
    csrf(&s, headers)?;
    Ok(s)
}
#[derive(Deserialize)]
pub struct ChallengeInput {
    address: String,
    purpose: String,
}
pub async fn challenge(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<ChallengeInput>,
) -> Result<Json<Value>> {
    origin(&app, &headers)?;
    app.admission.admit(peer.ip())?;
    if !valid_address(&input.address) {
        return Err(Error::bad("invalid wallet"));
    }
    let profile_id = if input.purpose == "login" {
        None
    } else {
        let s = authorized(&app, &headers).await?;
        if input.purpose != "add_wallet" {
            let id = input
                .purpose
                .strip_prefix("assignment:")
                .and_then(|v| Uuid::parse_str(v).ok())
                .ok_or(Error::bad("invalid purpose"))?;
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM assignments WHERE id=$1 AND profile_id=$2 AND candidate_wallet=$3 AND cancelled_at IS NULL AND accepted_at IS NULL AND proposed_at>now()-interval '7 days')")
                .bind(id).bind(s.profile_id).bind(&input.address).fetch_one(&app.db).await?;
            if !exists {
                return Err(Error::forbidden());
            }
        }
        Some(s.profile_id)
    };
    let mut tx = app.db.begin().await?;
    // Global durable bound across API instances. Do not give strangers an address-
    // specific quota they can spend to lock out a victim. Peer admission happens first.
    sqlx::query("SELECT pg_advisory_xact_lock(811205992)")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM challenges WHERE created_at>now()-interval '1 hour'",
    )
    .fetch_one(&mut *tx)
    .await?;
    if count >= 10000 {
        return Err(Error::limited());
    }
    let id = Uuid::new_v4();
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *tx)
        .await?;
    let expires = now + chrono::Duration::minutes(5);
    let message=format!("CL8Y Wallet Security\nAudience: wallet-security-api-v1\nOrigin: {}\nChain: {}\nAddress: {}\nPurpose: {}\nProfile: {}\nNonce: {}\nExpires: {}\nThis signature proves wallet control for the stated portal action only. It cannot authorize token recovery or a blockchain transaction.",app.origin,app.chain_id,input.address,input.purpose,profile_id.map(|v|v.to_string()).unwrap_or_else(||"new-session".into()),random_token(),expires.to_rfc3339());
    sqlx::query("INSERT INTO challenges(id,address,purpose,profile_id,message,expires_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(id).bind(input.address).bind(input.purpose).bind(profile_id).bind(&message).bind(expires).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"message":message,"expires_at":expires,"chain_id":app.chain_id}),
    ))
}
#[derive(Deserialize)]
pub struct VerifyInput {
    pub(crate) id: Uuid,
    public_key: String,
    signature: String,
}
pub async fn verify(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<VerifyInput>,
) -> Result<(HeaderMap, Json<Value>)> {
    origin(&app, &headers)?;
    // Fetch any existing session before holding a transaction connection.
    let proof_session = session(&app, &headers).await.ok();
    let mut tx = app.db.begin().await?;
    let row=sqlx::query("SELECT address,purpose,profile_id,message FROM challenges WHERE id=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE")
        .bind(input.id).fetch_optional(&mut *tx).await?.ok_or(Error::unauthorized())?;
    let address: String = row.get("address");
    let purpose: String = row.get("purpose");
    let profile: Option<Uuid> = row.get("profile_id");
    // A failed signature consumes the challenge too, bounding attempts and eliminating reuse.
    sqlx::query("UPDATE challenges SET used_at=now() WHERE id=$1")
        .bind(input.id)
        .execute(&mut *tx)
        .await?;
    if !verify_signature(
        &address,
        row.get::<String, _>("message").as_str(),
        &input.public_key,
        &input.signature,
    ) {
        tx.commit().await?;
        return Err(Error::unauthorized());
    }
    let mut out = HeaderMap::new();
    let result = if purpose == "login" {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&address)
            .execute(&mut *tx)
            .await?;
        let existing=sqlx::query("SELECT p.id,p.anchor_wallet FROM wallets w JOIN profiles p ON p.id=w.profile_id WHERE w.address=$1").bind(&address).fetch_optional(&mut *tx).await?;
        // Added wallets cannot authenticate as the anchor and inherit its privileges.
        let profile_id = if let Some(r) = existing {
            if r.get::<String, _>("anchor_wallet") != address {
                tx.commit().await?;
                return Err(Error::forbidden());
            }
            r.get::<Uuid, _>("id")
        } else {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO profiles(id,anchor_wallet) VALUES($1,$2)")
                .bind(id)
                .bind(&address)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO wallets(address,profile_id) VALUES($1,$2)")
                .bind(&address)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            id
        };
        let token = random_token();
        let csrf_token = random_token();
        sqlx::query("INSERT INTO sessions(token_hash,profile_id,csrf_token,expires_at) VALUES($1,$2,$3,now()+interval '8 hours')").bind(hash(&token)).bind(profile_id).bind(&csrf_token).execute(&mut *tx).await?;
        out.insert("set-cookie",format!("__Host-cw_session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800").parse().unwrap());
        json!({"csrf_token":csrf_token})
    } else {
        let s = proof_session.ok_or(Error::unauthorized())?;
        csrf(&s, &headers)?;
        if profile != Some(s.profile_id) {
            return Err(Error::forbidden());
        }
        if purpose == "add_wallet" {
            sqlx::query("INSERT INTO wallets(address,profile_id) VALUES($1,$2) ON CONFLICT(address) DO NOTHING").bind(&address).bind(s.profile_id).execute(&mut *tx).await?;
            let belongs: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM wallets WHERE address=$1 AND profile_id=$2)",
            )
            .bind(&address)
            .bind(s.profile_id)
            .fetch_one(&mut *tx)
            .await?;
            if !belongs {
                return Err(Error::bad("wallet already belongs to a different profile"));
            }
        } else {
            let id = Uuid::parse_str(
                purpose
                    .strip_prefix("assignment:")
                    .ok_or(Error::forbidden())?,
            )
            .map_err(|_| Error::forbidden())?;
            let result=sqlx::query("UPDATE assignments SET accepted_at=now() WHERE id=$1 AND profile_id=$2 AND candidate_wallet=$3 AND accepted_at IS NULL AND cancelled_at IS NULL AND proposed_at>now()-interval '7 days'")
                .bind(id).bind(s.profile_id).bind(&address).execute(&mut *tx).await?;
            if result.rows_affected() != 1 {
                return Err(Error::bad("consent unavailable"));
            }
        }
        json!({"verified":true})
    };
    tx.commit().await?;
    Ok((out, Json(result)))
}
pub async fn logout(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<Value>)> {
    authorized(&app, &headers).await?;
    if let Some(cookie) = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|x| x.trim().strip_prefix("__Host-cw_session="))
        })
    {
        sqlx::query("DELETE FROM sessions WHERE token_hash=$1")
            .bind(hash(cookie))
            .execute(&app.db)
            .await?;
    }
    let mut out = HeaderMap::new();
    out.insert(
        "set-cookie",
        "__Host-cw_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok((out, Json(json!({"ok":true}))))
}
#[cfg(test)]
mod tests {
    use super::*;
    use bech32::ToBase32;
    use k256::ecdsa::{signature::Signer, SigningKey};
    #[test]
    fn signature_binds_message_and_address() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let pk = key.verifying_key().to_encoded_point(true);
        let raw = pk.as_bytes();
        let address = bech32::encode(
            "terra",
            Ripemd160::digest(Sha256::digest(raw)).to_base32(),
            bech32::Variant::Bech32,
        )
        .unwrap();
        let msg =
            "Origin: https://security.example\nChain: columbus-5\nPurpose: login\nNonce: unique";
        let doc = json!({"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":STANDARD.encode(msg),"signer":address}}],"sequence":"0"});
        let sig: Signature = key.sign(doc.to_string().as_bytes());
        let sig = STANDARD.encode(sig.to_bytes());
        let pk = STANDARD.encode(raw);
        assert!(verify_signature(&address, msg, &pk, &sig));
        assert!(!verify_signature(
            &address,
            &msg.replace("columbus-5", "other"),
            &pk,
            &sig
        ));
        assert!(!verify_signature(
            &address,
            &msg.replace("login", "add_wallet"),
            &pk,
            &sig
        ));
        assert!(!verify_signature("terra1invalid", msg, &pk, &sig));
        assert!(valid_address(&address));
    }
}
#[cfg(test)]
mod independent_vector {
    use super::*;
    #[test]
    fn cosmjs_adr036_vector() {
        let v: Value =
            serde_json::from_str(include_str!("../tests/fixtures/adr036-cosmjs.json")).unwrap();
        let a = v["address"].as_str().unwrap();
        let m = v["message"].as_str().unwrap();
        let pk = v["public_key"].as_str().unwrap();
        let sig = v["signature"].as_str().unwrap();
        assert!(verify_signature(a, m, pk, sig));
        for changed in [
            m.replace("security.example", "evil.example"),
            m.replace("columbus-5", "phoenix-1"),
            m.replace("login", "assignment:case"),
        ] {
            assert!(!verify_signature(a, &changed, pk, sig));
        }
    }
}
