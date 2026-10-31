use crate::App;
use serde_json::json;
pub async fn run(app:App)->anyhow::Result<()> {
 let mut tick=tokio::time::interval(std::time::Duration::from_secs(15));
 loop {tick.tick().await;
 let mut tx=app.db.begin().await?;
 let leader:bool=sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(811205991)").fetch_one(&mut *tx).await?;
 if !leader {continue}
 // Explicit delivery hold. Never discard a warning or claim provider delivery.
 sqlx::query("UPDATE notification_outbox SET state='blocked',last_error_code='send_not_authorized' WHERE state='pending'").execute(&mut *tx).await?;
 let blocked:i64=sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE state='blocked'").fetch_one(&mut *tx).await?;
 sqlx::query("INSERT INTO worker_heartbeats(name,last_seen,source_sha,detail) VALUES('notifications',now(),$1,$2) ON CONFLICT(name) DO UPDATE SET last_seen=now(),source_sha=EXCLUDED.source_sha,detail=EXCLUDED.detail")
 .bind(&app.source_sha).bind(json!({"delivery_enabled":false,"blocked":blocked,"chain_ingestion":"unconfigured"})).execute(&mut *tx).await?;
 sqlx::query("DELETE FROM challenges WHERE created_at<now()-interval '7 days'").execute(&mut *tx).await?;
 sqlx::query("DELETE FROM sessions WHERE expires_at<now()-interval '1 day'").execute(&mut *tx).await?;
 tx.commit().await?;
 }
}
