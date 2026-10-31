use crate::{notifications, App};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

pub fn backoff(attempt: i32) -> i64 {
    15_i64
        .saturating_mul(2_i64.pow(attempt.clamp(0, 10) as u32))
        .min(3600)
}
pub fn uncertain_delivery(transport: &str, code: &str) -> bool {
    code == "delivery_uncertain"
        || (transport == "telegram"
            && ["transport_failure", "provider_invalid_response"].contains(&code))
}
async fn dispatch(app: &App) -> anyhow::Result<()> {
    // One claim immediately before each send; no serially waiting leased batch.
    // Only persisted Resend sends have an idempotency primitive. SMTP, Telegram and
    // unknown transports cannot be replayed after a crashed/expired in-flight send.
    sqlx::query("UPDATE notification_outbox SET state='failed',last_error_code='delivery_uncertain',locked_until=NULL WHERE state IN ('pending','blocked','sending') AND ((delivery_transport='resend' AND first_attempt_at<now()-interval '23 hours') OR (state='sending' AND locked_until<now() AND delivery_transport IS DISTINCT FROM 'resend'))").execute(&app.db).await?;
    for _ in 0..20 {
        let lease = Uuid::new_v4();
        let Some(row) = claim(app, lease).await? else {
            break;
        };
        let id: Uuid = row.get("id");
        let contact: Uuid = row.get("contact_id");
        let event: String = row.get("event_id");
        let template: String = row.get("template");
        let attempts: i32 = row.get("attempts");
        let transport: Option<String> = row.get("delivery_transport");
        let data=sqlx::query("SELECT c.kind,c.encrypted_destination,e.action,e.wallet,e.token,e.proposed_at,e.executable_at FROM contacts c JOIN security_events e ON e.id=$2 WHERE c.id=$1")
  .bind(contact).bind(event).fetch_one(&app.db).await?;
        let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM notification_outbox WHERE id=$1 AND lease_id=$2 AND state='sending' AND locked_until>now()+interval '30 seconds')").bind(id).bind(lease).fetch_one(&app.db).await?;
        if !current {
            continue;
        }
        let result=async {
   let destination=notifications::decrypt(app,&data.get::<Vec<u8>,_>("encrypted_destination")).map_err(|_|"contact_decrypt_failed")?;
   let deadline:DateTime<Utc>=data.get("executable_at");
   let text=match template.as_str() {
    "email_verify"|"telegram_verify"=>{
     if deadline<Utc::now(){return Err("verification_expired")}
     let token=notifications::decrypt(app,&row.get::<Option<Vec<u8>>,_>("encrypted_payload").ok_or("verification_payload_missing")?).map_err(|_|"payload_decrypt_failed")?;
     format!("Confirm your CL8Y {} channel by entering this one-use code at {}/#notifications:\n{}\nExpires {}. This does not grant wallet or recovery authority. Ignore if you did not request it.",data.get::<String,_>("kind"),app.origin,token,deadline.to_rfc3339())
    },
    _=>format!("Security timer started: {}\nWallet: {}\nToken: {}\nStarted: {}\nDeadline: {}\nReview, cancel or dispute at {}/#timers\nToken actions require your wallet and on-chain authority; never share your keys.",data.get::<String,_>("action"),data.get::<String,_>("wallet"),data.get::<Option<String>,_>("token").unwrap_or_else(||"Portal assignment/contact only".into()),data.get::<DateTime<Utc>,_>("proposed_at").to_rfc3339(),deadline.to_rfc3339(),app.origin)
   };
   let transport=transport.as_deref().ok_or("provider_unconfigured")?;
   notifications::deliver(app,transport,&destination,&text,&id.to_string()).await
  }.await;
        match result {
            Ok(()) => {
                sqlx::query("UPDATE notification_outbox SET state='sent',sent_at=now(),locked_until=NULL,last_error_code=NULL,encrypted_payload=NULL WHERE id=$1 AND lease_id=$2 AND state='sending'").bind(id).bind(lease).execute(&app.db).await?;
            }
            Err(code) => {
                let blocked = [
                    "provider_unconfigured",
                    "provider_configuration_changed",
                    "sandbox_destination_not_allowed",
                ]
                .contains(&code);
                let failed = (!blocked && attempts >= 8)
                    || uncertain_delivery(transport.as_deref().unwrap_or(""), code)
                    || [
                        "verification_expired",
                        "provider_rejected",
                        "contact_decrypt_failed",
                        "payload_decrypt_failed",
                    ]
                    .contains(&code);
                sqlx::query("UPDATE notification_outbox SET state=$2,last_error_code=$3,locked_until=NULL,next_attempt_at=now()+make_interval(secs=>$4),attempts=CASE WHEN $5 THEN attempts-1 ELSE attempts END,first_attempt_at=CASE WHEN $5 AND attempts=1 THEN NULL ELSE first_attempt_at END,delivery_transport=CASE WHEN $5 AND attempts=1 THEN NULL ELSE delivery_transport END WHERE id=$1 AND lease_id=$6 AND state='sending'")
    .bind(id).bind(if failed{"failed"}else if blocked{"blocked"}else{"pending"}).bind(if uncertain_delivery(transport.as_deref().unwrap_or(""),code){"delivery_uncertain"}else{code}).bind(if blocked{300.0}else{backoff(attempts) as f64}).bind(blocked).bind(lease).execute(&app.db).await?;
            }
        }
    }
    // A lease lost at final attempt must become visible failure, never remain stuck sending.
    sqlx::query("UPDATE notification_outbox SET state='failed',last_error_code='delivery_uncertain',locked_until=NULL WHERE state='sending' AND attempts>=8 AND locked_until<now()").execute(&app.db).await?;
    Ok(())
}
pub(crate) async fn claim(app: &App, lease: Uuid) -> anyhow::Result<Option<sqlx::postgres::PgRow>> {
    Ok(sqlx::query("UPDATE notification_outbox o SET state='sending',attempts=attempts+1,locked_until=now()+interval '2 minutes',lease_id=$1,first_attempt_at=COALESCE(first_attempt_at,now()),delivery_transport=COALESCE(delivery_transport,(SELECT CASE WHEN c.kind='email' THEN $2 ELSE 'telegram' END FROM contacts c WHERE c.id=o.contact_id)) WHERE id=(SELECT id FROM notification_outbox WHERE ((state IN ('pending','blocked') AND next_attempt_at<=now() AND (delivery_transport IS DISTINCT FROM 'resend' OR first_attempt_at IS NULL OR first_attempt_at>now()-interval '23 hours')) OR (state='sending' AND locked_until<now() AND first_attempt_at>now()-interval '23 hours' AND delivery_transport='resend')) AND attempts<8 ORDER BY CASE WHEN template='timer_start' THEN 0 ELSE 1 END,created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,event_id,contact_id,template,encrypted_payload,attempts,delivery_transport,first_attempt_at").bind(lease).bind(notifications::email_transport()).fetch_optional(&app.db).await?)
}
pub async fn tick(app: &App) -> anyhow::Result<()> {
    crate::chain::fanout(app).await?;
    dispatch(app).await?;
    // Telegram update offset and pairing consumption commit together. No message body is logged.
    let telegram_ok = notifications::poll_telegram(app).await.is_ok();
    let mut tx = app.db.begin().await?;
    if !sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(811205991)")
        .fetch_one(&mut *tx)
        .await?
    {
        return Ok(());
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification_outbox WHERE state IN ('pending','blocked','sending')",
    )
    .fetch_one(&mut *tx)
    .await?;
    let failed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE state='failed'")
            .fetch_one(&mut *tx)
            .await?;
    let oldest:Option<DateTime<Utc>>=sqlx::query_scalar("SELECT min(created_at) FROM notification_outbox WHERE state IN ('pending','blocked','sending')").fetch_one(&mut *tx).await?;
    let fanout_pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM controller_fanout WHERE completed_at IS NULL")
            .fetch_one(&mut *tx)
            .await?;
    let rejected: Option<i64> =
        sqlx::query_scalar("SELECT rejected FROM verification_budget WHERE id=1")
            .fetch_optional(&mut *tx)
            .await?;
    sqlx::query("INSERT INTO worker_heartbeats(name,last_seen,source_sha,detail) VALUES('notifications',now(),$1,$2) ON CONFLICT(name) DO UPDATE SET last_seen=now(),source_sha=EXCLUDED.source_sha,detail=EXCLUDED.detail")
 .bind(&app.source_sha).bind(json!({"email_ready":notifications::email_ready(),"telegram_ready":notifications::telegram_ready(),"telegram_poll_ok":telegram_ok,"pending":pending,"failed":failed,"oldest_pending":oldest,"controller_fanout_pending":fanout_pending,"verification_rejections":rejected.unwrap_or(0)})).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM challenges WHERE created_at<now()-interval '7 days'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at<now()-interval '1 day'")
        .execute(&mut *tx)
        .await?;
    // Bounded PII retention: retain delivery outcomes, replace expired undelivered
    // destination data with an explicit visible failure before cryptographic erasure.
    sqlx::query("UPDATE notification_outbox o SET state='failed',last_error_code='contact_retention_expired',locked_until=NULL WHERE state IN ('pending','blocked','sending') AND EXISTS(SELECT 1 FROM contacts c WHERE c.id=o.contact_id AND (c.removal_at<now()-interval '30 days' OR c.deleted_at<now()-interval '30 days' OR (c.verified_at IS NULL AND c.created_at<now()-interval '30 days')))").execute(&mut *tx).await?;
    sqlx::query("UPDATE contacts SET encrypted_destination=decode('','hex'),deleted_at=COALESCE(deleted_at,now()) WHERE (removal_at<now()-interval '30 days' OR deleted_at<now()-interval '30 days' OR (verified_at IS NULL AND created_at<now()-interval '30 days')) AND octet_length(encrypted_destination)>0").execute(&mut *tx).await?;
    sqlx::query("UPDATE notification_outbox SET encrypted_payload=NULL WHERE state IN ('failed','sent') AND created_at<now()-interval '1 day'").execute(&mut *tx).await?;
    sqlx::query("DELETE FROM contact_verifications WHERE expires_at<now()-interval '1 day'")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM verification_destinations WHERE next_allowed_at<now()-interval '1 day'",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
pub async fn run(app: App) -> anyhow::Result<()> {
    tokio::spawn(crate::chain::run(app.clone()));
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        interval.tick().await;
        if tick(&app).await.is_err() {
            // Fixed diagnostic code only: database/provider errors can contain sensitive destinations.
            eprintln!("notification_tick_failed");
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_is_bounded() {
        assert!(uncertain_delivery("telegram", "transport_failure"));
        assert!(uncertain_delivery("telegram", "provider_invalid_response"));
        assert!(uncertain_delivery("smtp", "delivery_uncertain"));
        assert!(!uncertain_delivery("email", "provider_invalid_response"));
        assert!(!uncertain_delivery("telegram", "provider_rate_limit"));
        assert_eq!(backoff(1), 30);
        assert_eq!(backoff(99), 3600);
    }
}
