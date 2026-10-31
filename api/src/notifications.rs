use crate::{auth, App, Error, Result};
use aes_gcm::{
    aead::{rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, KeyInit,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use std::env;
use uuid::Uuid;

pub fn encrypt(app: &App, plain: &str) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(app.contact_key.as_ref())
        .map_err(|_| Error::bad("encryption unavailable"))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut data = nonce.to_vec();
    data.extend(
        cipher
            .encrypt((&nonce).into(), plain.as_bytes())
            .map_err(|_| Error::bad("encryption unavailable"))?,
    );
    Ok(data)
}
pub fn decrypt(app: &App, data: &[u8]) -> anyhow::Result<String> {
    anyhow::ensure!(data.len() >= 28, "invalid encrypted payload");
    let cipher = Aes256Gcm::new_from_slice(app.contact_key.as_ref())
        .map_err(|_| anyhow::anyhow!("key unavailable"))?;
    let value = cipher
        .decrypt((&data[..12]).into(), &data[12..])
        .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
    Ok(String::from_utf8(value)?)
}
pub fn email_ready() -> bool {
    env::var("RESEND_API_KEY").is_ok_and(|v| !v.is_empty())
        && env::var("MAIL_FROM").is_ok_and(|v| !v.is_empty())
}
pub fn telegram_ready() -> bool {
    env::var("TELEGRAM_BOT_TOKEN").is_ok_and(|v| !v.is_empty())
        && env::var("TELEGRAM_BOT_USERNAME").is_ok_and(|v| !v.is_empty())
}
pub async fn record(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    profile: Uuid,
    action: &str,
    wallet: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<()> {
    sqlx::query("INSERT INTO security_events(id,profile_id,action,wallet,proposed_at,executable_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
 .bind(id).bind(profile).bind(action).bind(wallet).bind(start).bind(end).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO notification_outbox(id,event_id,contact_id) SELECT gen_random_uuid(),$1,id FROM contacts WHERE profile_id=$2 AND verified_at<=$3 AND (activation_at IS NULL OR activation_at<=$3) AND deleted_at IS NULL AND (removal_at IS NULL OR removal_at>$3) ON CONFLICT DO NOTHING")
 .bind(id).bind(profile).bind(start).execute(&mut **tx).await?;
    Ok(())
}
pub async fn list(app: &App, profile: Uuid) -> Result<Vec<Value>> {
    Ok(sqlx::query("SELECT id,kind,verified_at,activation_at,removal_at,now() AS server_now FROM contacts WHERE profile_id=$1 AND deleted_at IS NULL").bind(profile).fetch_all(&app.db).await?.into_iter().map(|r|{
 let now:DateTime<Utc>=r.get("server_now");let activation:Option<DateTime<Utc>>=r.get("activation_at");let removal:Option<DateTime<Utc>>=r.get("removal_at");
 json!({"id":r.get::<Uuid,_>("id"),"kind":r.get::<String,_>("kind"),"status":if removal.is_some_and(|t|t<=now){"removed"}else if r.get::<Option<DateTime<Utc>>,_>("verified_at").is_none(){"unverified"}else if activation.is_some_and(|t|t>now){"pending"}else{"verified"},"removal_at":removal,"activation_at":activation})}).collect())
}
async fn contact_admission(tx: &mut Transaction<'_, Postgres>, profile: Uuid) -> Result<()> {
    sqlx::query("SELECT id FROM profiles WHERE id=$1 FOR UPDATE")
        .bind(profile)
        .execute(&mut **tx)
        .await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM contacts WHERE profile_id=$1 AND created_at>now()-interval '24 hours'").bind(profile).fetch_one(&mut **tx).await?;
    if count >= 5 {
        return Err(Error::limited());
    }
    Ok(())
}
async fn enqueue_verification(
    app: &App,
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    profile: Uuid,
    anchor: &str,
    template: &str,
    token: &str,
) -> Result<()> {
    let event = format!("contact:{id}:{template}");
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO security_events(id,profile_id,action,wallet,proposed_at,executable_at) VALUES($1,$2,$3,$4,$5,$6)")
 .bind(&event).bind(profile).bind(template).bind(anchor).bind(now).bind(now+chrono::Duration::minutes(30)).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO notification_outbox(id,event_id,contact_id,template,encrypted_payload) VALUES($1,$2,$3,$4,$5)")
 .bind(Uuid::new_v4()).bind(event).bind(id).bind(template).bind(encrypt(app,token)?).execute(&mut **tx).await?;
    Ok(())
}
#[derive(Deserialize)]
pub struct Email {
    address: String,
}
pub(crate) async fn verification_budget(
    app: &App,
    tx: &mut Transaction<'_, Postgres>,
    destination: &str,
) -> Result<bool> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(app.contact_key.as_ref())
        .map_err(|_| Error::bad("verification unavailable"))?;
    mac.update(b"cl8y-contact-cooldown-v1\0");
    mac.update(destination.to_lowercase().as_bytes());
    let hash = hex::encode(mac.finalize().into_bytes());
    sqlx::query("INSERT INTO verification_budget(id,day,accepted,rejected) VALUES(1,current_date,0,0) ON CONFLICT DO NOTHING").execute(&mut **tx).await?;
    let global = sqlx::query(
        "SELECT accepted,day=current_date AS today FROM verification_budget WHERE id=1 FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await?;
    if !global.get::<bool, _>("today") {
        sqlx::query("UPDATE verification_budget SET day=current_date,accepted=0 WHERE id=1")
            .execute(&mut **tx)
            .await?;
    }
    let rejected = global.get::<bool, _>("today") && global.get::<i32, _>("accepted") >= 500;
    let cooldown:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM verification_destinations WHERE destination_hash=$1 AND next_allowed_at>now())").bind(&hash).fetch_one(&mut **tx).await?;
    if rejected || cooldown {
        sqlx::query("UPDATE verification_budget SET rejected=rejected+1 WHERE id=1")
            .execute(&mut **tx)
            .await?;
        return Ok(false);
    }
    sqlx::query("INSERT INTO verification_destinations(destination_hash,next_allowed_at) VALUES($1,now()+interval '1 hour') ON CONFLICT(destination_hash) DO UPDATE SET next_allowed_at=EXCLUDED.next_allowed_at").bind(hash).execute(&mut **tx).await?;
    sqlx::query("UPDATE verification_budget SET accepted=accepted+1 WHERE id=1")
        .execute(&mut **tx)
        .await?;
    Ok(true)
}
pub async fn email(
    State(app): State<App>,
    headers: HeaderMap,
    Json(p): Json<Email>,
) -> Result<Json<Value>> {
    let s = auth::authorized(&app, &headers).await?;
    if !email_ready() {
        return Err(Error(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "email provider unavailable; verification was not sent",
        ));
    }
    let address = p.address.trim();
    if address.len() > 254
        || address.chars().any(|c| c.is_whitespace() || c.is_control())
        || address.matches('@').count() != 1
        || !address.split('@').nth(1).is_some_and(|s| s.contains('.'))
    {
        return Err(Error::bad("invalid email address"));
    }
    let mut tx = app.db.begin().await?;
    contact_admission(&mut tx, s.profile_id).await?;
    if !verification_budget(&app, &mut tx, address).await? {
        tx.commit().await?;
        return Err(Error::limited());
    }

    let id = Uuid::new_v4();
    let token = auth::random_token();
    sqlx::query("INSERT INTO contacts(id,profile_id,kind,encrypted_destination,consent_at) VALUES($1,$2,'email',$3,now())").bind(id).bind(s.profile_id).bind(encrypt(&app,address)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO contact_verifications(token_hash,contact_id,expires_at,purpose) VALUES($1,$2,now()+interval '30 minutes','email')").bind(auth::hash(&token)).bind(id).execute(&mut *tx).await?;
    enqueue_verification(
        &app,
        &mut tx,
        id,
        s.profile_id,
        &s.anchor,
        "email_verify",
        &token,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"queued":true,"sent":false,"status":"unverified","message":"Verification queued; delivery is not yet confirmed."}),
    ))
}
#[derive(Deserialize)]
pub struct Verification {
    token: String,
}
async fn verify_contact(
    app: &App,
    s: auth::Session,
    token: &str,
    kind: &str,
) -> Result<Json<Value>> {
    if token.len() != 64 {
        return Err(Error::bad("invalid or expired verification"));
    }
    let mut tx = app.db.begin().await?;
    let delay: i32 =
        sqlx::query_scalar("SELECT assignment_delay_seconds FROM profiles WHERE id=$1 FOR UPDATE")
            .bind(s.profile_id)
            .fetch_one(&mut *tx)
            .await?;
    let row=sqlx::query("SELECT c.id,now() AS server_now FROM contact_verifications v JOIN contacts c ON c.id=v.contact_id WHERE v.token_hash=$1 AND v.purpose=$2 AND v.used_at IS NULL AND v.expires_at>now() AND c.profile_id=$3 AND c.kind=$4 AND c.deleted_at IS NULL AND c.verified_at IS NULL FOR UPDATE OF v,c")
 .bind(auth::hash(token)).bind(kind).bind(s.profile_id).bind(if kind=="email"{"email"}else{"telegram"}).fetch_optional(&mut *tx).await?.ok_or(Error::bad("invalid or expired verification"))?;
    let id: Uuid = row.get("id");
    let now: DateTime<Utc> = row.get("server_now");
    let has_old:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contacts WHERE profile_id=$1 AND kind=$2 AND id<>$3 AND verified_at IS NOT NULL AND deleted_at IS NULL AND (removal_at IS NULL OR removal_at>now()))")
 .bind(s.profile_id).bind(if kind=="email"{"email"}else{"telegram"}).bind(id).fetch_one(&mut *tx).await?;
    let activation = if has_old {
        now + chrono::Duration::seconds(delay.into())
    } else {
        now
    };
    // Warn every previous verified contact and preserve it. New channel never silently replaces old.
    record(
        &mut tx,
        &format!("contact:{id}:activate"),
        s.profile_id,
        "contact_addition_start",
        &s.anchor,
        now,
        activation,
    )
    .await?;
    sqlx::query("UPDATE contacts SET verified_at=now(),activation_at=$2 WHERE id=$1")
        .bind(id)
        .bind(activation)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE contact_verifications SET used_at=now() WHERE token_hash=$1")
        .bind(auth::hash(token))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"verified":true,"activation_at":activation,"status":if has_old{"pending"}else{"verified"}}),
    ))
}
pub async fn verify_email(
    State(app): State<App>,
    headers: HeaderMap,
    Json(p): Json<Verification>,
) -> Result<Json<Value>> {
    let s = auth::authorized(&app, &headers).await?;
    verify_contact(&app, s, &p.token, "email").await
}
pub async fn telegram(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>> {
    let s = auth::authorized(&app, &headers).await?;
    if !telegram_ready() {
        return Err(Error(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Telegram provider unavailable; pairing was not started",
        ));
    }
    let username = env::var("TELEGRAM_BOT_USERNAME").unwrap_or_default();
    if username.is_empty()
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(Error::bad("Telegram configuration invalid"));
    }
    let mut tx = app.db.begin().await?;
    contact_admission(&mut tx, s.profile_id).await?;
    let id = Uuid::new_v4();
    let token = auth::random_token();
    sqlx::query("INSERT INTO contacts(id,profile_id,kind,encrypted_destination,consent_at) VALUES($1,$2,'telegram',$3,now())").bind(id).bind(s.profile_id).bind(encrypt(&app,"")?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO contact_verifications(token_hash,contact_id,expires_at,purpose) VALUES($1,$2,now()+interval '15 minutes','telegram_pair')").bind(auth::hash(&token)).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"pairing_url":format!("https://t.me/{username}?start={token}"),"status":"unverified","message":"Start the bot, then paste its confirmation code in this portal."}),
    ))
}
pub async fn confirm_telegram(
    State(app): State<App>,
    headers: HeaderMap,
    Json(p): Json<Verification>,
) -> Result<Json<Value>> {
    let s = auth::authorized(&app, &headers).await?;
    verify_contact(&app, s, &p.token, "telegram_confirm").await
}
pub async fn remove(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    let s = auth::authorized(&app, &headers).await?;
    let mut tx = app.db.begin().await?;
    let delay: i32 =
        sqlx::query_scalar("SELECT assignment_delay_seconds FROM profiles WHERE id=$1 FOR UPDATE")
            .bind(s.profile_id)
            .fetch_one(&mut *tx)
            .await?;
    let row=sqlx::query("SELECT verified_at,removal_at,now() AS server_now FROM contacts WHERE id=$1 AND profile_id=$2 AND deleted_at IS NULL FOR UPDATE").bind(id).bind(s.profile_id).fetch_optional(&mut *tx).await?.ok_or(Error::forbidden())?;
    if row.get::<Option<DateTime<Utc>>, _>("removal_at").is_some() {
        tx.commit().await?;
        return Ok(Json(json!({"ok":true})));
    }
    let now: DateTime<Utc> = row.get("server_now");
    let removal = now + chrono::Duration::seconds(delay.into());
    if row.get::<Option<DateTime<Utc>>, _>("verified_at").is_some() {
        record(
            &mut tx,
            &format!("contact:{id}:remove"),
            s.profile_id,
            "contact_removal_start",
            &s.anchor,
            now,
            removal,
        )
        .await?;
        sqlx::query("UPDATE contacts SET removal_at=$2 WHERE id=$1")
            .bind(id)
            .bind(removal)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("UPDATE contacts SET deleted_at=now() WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"ok":true,"removal_at":removal})))
}
// Responses and transport errors are never logged: provider bodies/URLs may contain PII or tokens.
pub async fn deliver(
    app: &App,
    kind: &str,
    destination: &str,
    text: &str,
    id: &str,
) -> std::result::Result<(), &'static str> {
    // Explicit sandbox destination allowlist enables owned provider checks without real-user sends.
    if let Ok(allowed) = env::var("NOTIFICATION_SANDBOX_DESTINATIONS") {
        if !allowed.split(',').any(|v| v.trim() == destination) {
            return Err("sandbox_destination_not_allowed");
        }
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "transport_configuration")?;
    let response = match kind {
        "email" => {
            if !email_ready() {
                return Err("provider_unconfigured");
            }
            client.post("https://api.resend.com/emails").bearer_auth(env::var("RESEND_API_KEY").map_err(|_|"provider_unconfigured")?).header("Idempotency-Key",id)
  .json(&json!({"from":env::var("MAIL_FROM").map_err(|_|"provider_unconfigured")?,"to":[destination],"subject":"CL8Y wallet security notice","text":text})).send().await
        }
        "telegram" => {
            let token = env::var("TELEGRAM_BOT_TOKEN").map_err(|_| "provider_unconfigured")?;
            client.post(format!("https://api.telegram.org/bot{token}/sendMessage")).json(&json!({"chat_id":destination,"text":text,"link_preview_options":{"is_disabled":true}})).send().await
        }
        _ => return Err("unsupported_channel"),
    };
    let response = response.map_err(|_| "transport_failure")?;
    if response.status().is_success() {
        let value: Value = response
            .json()
            .await
            .map_err(|_| "provider_invalid_response")?;
        let accepted = if kind == "telegram" {
            value["ok"] == true && value["result"]["message_id"].as_i64().is_some()
        } else {
            value["id"].as_str().is_some()
        };
        let _ = app;
        if accepted {
            Ok(())
        } else {
            Err("provider_rejected")
        }
    } else if response.status().as_u16() == 429 {
        Err("provider_rate_limit")
    } else if response.status().is_server_error() {
        Err("provider_temporary")
    } else {
        Err("provider_rejected")
    }
}
pub async fn poll_telegram(app: &App) -> anyhow::Result<()> {
    if !telegram_ready() {
        return Ok(());
    }
    let mut tx = app.db.begin().await?;
    if !sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(811205993)")
        .fetch_one(&mut *tx)
        .await?
    {
        return Ok(());
    }
    sqlx::query("INSERT INTO telegram_checkpoints(bot_name,next_update_id) VALUES('security',0) ON CONFLICT DO NOTHING").execute(&mut *tx).await?;
    let offset: i64 = sqlx::query_scalar(
        "SELECT next_update_id FROM telegram_checkpoints WHERE bot_name='security' FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let token = env::var("TELEGRAM_BOT_TOKEN")?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let response = client
        .post(format!("https://api.telegram.org/bot{token}/getUpdates"))
        .json(&json!({"offset":offset,"limit":20,"timeout":0,"allowed_updates":["message"]}))
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("telegram poll unavailable"))?;
    let data: Value = response
        .json()
        .await
        .map_err(|_| anyhow::anyhow!("telegram poll invalid"))?;
    if !data["ok"].as_bool().unwrap_or(false) {
        return Err(anyhow::anyhow!("telegram poll rejected"));
    }
    for update in data["result"].as_array().unwrap_or(&vec![]) {
        let Some(update_id) = update["update_id"].as_i64() else {
            continue;
        };
        sqlx::query("UPDATE telegram_checkpoints SET next_update_id=GREATEST(next_update_id,$1) WHERE bot_name='security'").bind(update_id+1).execute(&mut *tx).await?;
        if update["message"]["chat"]["type"] != "private" {
            continue;
        }
        let Some(text) = update["message"]["text"].as_str() else {
            continue;
        };
        let Some(pair) = text.strip_prefix("/start ") else {
            continue;
        };
        if pair.len() != 64 {
            continue;
        }
        let Some(chat) = update["message"]["chat"]["id"].as_i64() else {
            continue;
        };
        let row=sqlx::query("SELECT c.id,c.profile_id,p.anchor_wallet FROM contact_verifications v JOIN contacts c ON c.id=v.contact_id JOIN profiles p ON p.id=c.profile_id WHERE v.token_hash=$1 AND v.purpose='telegram_pair' AND v.used_at IS NULL AND v.expires_at>now() AND c.deleted_at IS NULL FOR UPDATE OF v,c")
  .bind(auth::hash(pair)).fetch_optional(&mut *tx).await?;
        let Some(row) = row else { continue };
        let id: Uuid = row.get("id");
        let profile: Uuid = row.get("profile_id");
        let anchor: String = row.get("anchor_wallet");
        sqlx::query("UPDATE contacts SET encrypted_destination=$2 WHERE id=$1")
            .bind(id)
            .bind(
                encrypt(app, &chat.to_string())
                    .map_err(|_| anyhow::anyhow!("encryption unavailable"))?,
            )
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE contact_verifications SET used_at=now() WHERE token_hash=$1")
            .bind(auth::hash(pair))
            .execute(&mut *tx)
            .await?;
        let confirm = auth::random_token();
        sqlx::query("INSERT INTO contact_verifications(token_hash,contact_id,expires_at,purpose) VALUES($1,$2,now()+interval '15 minutes','telegram_confirm')").bind(auth::hash(&confirm)).bind(id).execute(&mut *tx).await?;
        enqueue_verification(
            app,
            &mut tx,
            id,
            profile,
            &anchor,
            "telegram_verify",
            &confirm,
        )
        .await
        .map_err(|_| anyhow::anyhow!("verification storage unavailable"))?;
    }
    tx.commit().await?;
    Ok(())
}
