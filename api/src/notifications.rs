use crate::{App,Error,Result,auth};
use axum::{extract::{State,Path},http::HeaderMap,Json};
use serde::Deserialize;
use serde_json::{json,Value};
use sqlx::{Row,Postgres,Transaction};
use uuid::Uuid;
use chrono::{DateTime,Utc};
pub async fn record(tx:&mut Transaction<'_,Postgres>,id:&str,profile:Uuid,action:&str,wallet:&str,start:DateTime<Utc>,end:DateTime<Utc>)->Result<()> {
 sqlx::query("INSERT INTO security_events(id,profile_id,action,wallet,proposed_at,executable_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
 .bind(id).bind(profile).bind(action).bind(wallet).bind(start).bind(end).execute(&mut **tx).await?;
 sqlx::query("INSERT INTO notification_outbox(id,event_id,contact_id) SELECT gen_random_uuid(),$1,id FROM contacts WHERE profile_id=$2 AND verified_at IS NOT NULL AND deleted_at IS NULL AND (removal_at IS NULL OR removal_at>now()) ON CONFLICT DO NOTHING")
 .bind(id).bind(profile).execute(&mut **tx).await?;Ok(())
}
pub async fn list(app:&App,profile:Uuid)->Result<Vec<Value>> {
 Ok(sqlx::query("SELECT id,kind,verified_at,removal_at FROM contacts WHERE profile_id=$1 AND deleted_at IS NULL").bind(profile).fetch_all(&app.db).await?.into_iter().map(|r|json!({"id":r.get::<Uuid,_>("id"),"kind":r.get::<String,_>("kind"),"status":if r.get::<Option<DateTime<Utc>>,_>("verified_at").is_some(){"verified"}else{"unverified"},"removal_at":r.get::<Option<DateTime<Utc>>,_>("removal_at")})).collect())
}
#[derive(Deserialize)]
pub struct Email {address:String}
pub async fn email(State(app):State<App>,headers:HeaderMap,Json(p):Json<Email>)->Result<Json<Value>> {
 auth::authorized(&app,&headers).await?;let _=p.address;
 Err(Error(axum::http::StatusCode::SERVICE_UNAVAILABLE,"email delivery is not authorized/configured; verification was not sent"))
}
#[derive(Deserialize)]
pub struct Verification {token:String}
pub async fn verify_email(State(app):State<App>,headers:HeaderMap,Json(p):Json<Verification>)->Result<Json<Value>> {
 auth::authorized(&app,&headers).await?;let _=p.token;Err(Error::bad("verification unavailable"))
}
pub async fn telegram(State(app):State<App>,headers:HeaderMap)->Result<Json<Value>> {
 auth::authorized(&app,&headers).await?;Err(Error(axum::http::StatusCode::SERVICE_UNAVAILABLE,"Telegram pairing is not configured; no message was sent"))
}
pub async fn remove(State(app):State<App>,headers:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>> {
 let s=auth::authorized(&app,&headers).await?;let mut tx=app.db.begin().await?;
 let delay:i32=sqlx::query_scalar("SELECT assignment_delay_seconds FROM profiles WHERE id=$1 FOR UPDATE").bind(s.profile_id).fetch_one(&mut *tx).await?;
 let row=sqlx::query("SELECT verified_at,removal_at,now() AS server_now FROM contacts WHERE id=$1 AND profile_id=$2 AND deleted_at IS NULL FOR UPDATE").bind(id).bind(s.profile_id).fetch_optional(&mut *tx).await?.ok_or(Error::forbidden())?;
 if row.get::<Option<DateTime<Utc>>,_>("removal_at").is_some(){return Ok(Json(json!({"ok":true})))}
 let now:DateTime<Utc>=row.get("server_now");let removal=now+chrono::Duration::seconds(delay.into());
 if row.get::<Option<DateTime<Utc>>,_>("verified_at").is_some(){
 // Snapshot the old contact into outbox before it can be disabled.
 record(&mut tx,&format!("contact:{id}:remove"),s.profile_id,"contact_removal_start",&s.anchor,now,removal).await?;
 sqlx::query("UPDATE contacts SET removal_at=$2 WHERE id=$1").bind(id).bind(removal).execute(&mut *tx).await?;
 }else{sqlx::query("UPDATE contacts SET deleted_at=now() WHERE id=$1").bind(id).execute(&mut *tx).await?;}
 tx.commit().await?;Ok(Json(json!({"ok":true,"removal_at":removal})))
}
