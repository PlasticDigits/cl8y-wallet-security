use crate::{App,Error,Result,auth};
use axum::{extract::{State,Path},http::HeaderMap,Json};
use serde::Deserialize;
use serde_json::{Value,json};
use sqlx::Row;
use uuid::Uuid;
use chrono::{DateTime,Utc};
pub async fn list(app:&App,profile:Uuid)->Result<Vec<Value>> {
 Ok(sqlx::query("SELECT *,CASE WHEN cancelled_at IS NOT NULL THEN 'cancelled' WHEN removal_at<=now() THEN 'removed' WHEN accepted_at IS NULL THEN 'awaiting_consent' WHEN executable_at>now() THEN 'pending' ELSE 'active' END AS status FROM assignments WHERE profile_id=$1 ORDER BY proposed_at DESC LIMIT 100")
 .bind(profile).fetch_all(&app.db).await?.into_iter().map(|r|json!({"id":r.get::<Uuid,_>("id"),"owner_wallet":r.get::<String,_>("owner_wallet"),"candidate_wallet":r.get::<String,_>("candidate_wallet"),"role":r.get::<String,_>("role"),"status":r.get::<String,_>("status"),"proposed_at":r.get::<DateTime<Utc>,_>("proposed_at"),"executable_at":r.get::<DateTime<Utc>,_>("executable_at"),"delay_seconds":r.get::<i32,_>("delay_seconds"),"accepted_at":r.get::<Option<DateTime<Utc>>,_>("accepted_at"),"removal_at":r.get::<Option<DateTime<Utc>>,_>("removal_at")})).collect())
}
#[derive(Deserialize)]
pub struct Proposal {candidate_wallet:String,role:String}
pub async fn propose(State(app):State<App>,headers:HeaderMap,Json(p):Json<Proposal>)->Result<Json<Value>> {
 let s=auth::authorized(&app,&headers).await?;
 if !auth::valid_address(&p.candidate_wallet)||p.candidate_wallet==s.anchor|| !["guardian","recovery","notification"].contains(&p.role.as_str()){return Err(Error::bad("invalid candidate or role"))}
 let mut tx=app.db.begin().await?;
 let delay:i32=sqlx::query_scalar("SELECT assignment_delay_seconds FROM profiles WHERE id=$1 FOR UPDATE").bind(s.profile_id).fetch_one(&mut *tx).await?;
 let count:i64=sqlx::query_scalar("SELECT count(*) FROM assignments WHERE profile_id=$1 AND proposed_at>now()-interval '24 hours'").bind(s.profile_id).fetch_one(&mut *tx).await?;
 if count>=20{return Err(Error::limited())}
 // Replacement cancels only pending proposals, preserving all active assignments.
 sqlx::query("UPDATE assignments SET cancelled_at=now() WHERE profile_id=$1 AND candidate_wallet=$2 AND role=$3 AND cancelled_at IS NULL AND (accepted_at IS NULL OR executable_at>now())")
 .bind(s.profile_id).bind(&p.candidate_wallet).bind(&p.role).execute(&mut *tx).await?;
 let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM assignments WHERE profile_id=$1 AND candidate_wallet=$2 AND role=$3 AND accepted_at IS NOT NULL AND executable_at<=now() AND cancelled_at IS NULL AND (removal_at IS NULL OR removal_at>now()))")
 .bind(s.profile_id).bind(&p.candidate_wallet).bind(&p.role).fetch_one(&mut *tx).await?;
 if active{return Err(Error::bad("active assignment already exists"))}
 let id=Uuid::new_v4();let now:DateTime<Utc>=sqlx::query_scalar("SELECT now()").fetch_one(&mut *tx).await?;let deadline=now+chrono::Duration::seconds(delay.into());
 sqlx::query("INSERT INTO assignments(id,profile_id,owner_wallet,candidate_wallet,role,executable_at,delay_seconds) VALUES($1,$2,$3,$4,$5,$6,$7)")
 .bind(id).bind(s.profile_id).bind(&s.anchor).bind(p.candidate_wallet).bind(p.role).bind(deadline).bind(delay).execute(&mut *tx).await?;
 crate::notifications::record(&mut tx,&format!("assignment:{id}:start"),s.profile_id,"assignment_start",&s.anchor,now,deadline).await?;
 tx.commit().await?;
 Ok(Json(json!({"id":id,"status":"awaiting_consent","executable_at":deadline,"delay_seconds":delay})))
}
pub async fn cancel(State(app):State<App>,headers:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>> {
 let s=auth::authorized(&app,&headers).await?;let mut tx=app.db.begin().await?;
 // Use same lock order as proposal to make replacement/cancellation race safe.
 let current_delay:i32=sqlx::query_scalar("SELECT assignment_delay_seconds FROM profiles WHERE id=$1 FOR UPDATE").bind(s.profile_id).fetch_one(&mut *tx).await?;
 let row=sqlx::query("SELECT *,now() AS server_now FROM assignments WHERE id=$1 AND profile_id=$2 FOR UPDATE").bind(id).bind(s.profile_id).fetch_optional(&mut *tx).await?.ok_or(Error::forbidden())?;
 let now:DateTime<Utc>=row.get("server_now");let deadline:DateTime<Utc>=row.get("executable_at");
 if row.get::<Option<DateTime<Utc>>,_>("cancelled_at").is_some()||row.get::<Option<DateTime<Utc>>,_>("removal_at").is_some(){tx.commit().await?;return Ok(Json(json!({"ok":true})))}
 if row.get::<Option<DateTime<Utc>>,_>("accepted_at").is_none() || deadline>now {
 sqlx::query("UPDATE assignments SET cancelled_at=now() WHERE id=$1").bind(id).execute(&mut *tx).await?;
 }else{
 let delay=current_delay.max(row.get::<i32,_>("delay_seconds"));let removal=now+chrono::Duration::seconds(delay.into());
 sqlx::query("UPDATE assignments SET removal_at=$2 WHERE id=$1").bind(id).bind(removal).execute(&mut *tx).await?;
 crate::notifications::record(&mut tx,&format!("assignment:{id}:removal"),s.profile_id,"assignment_removal_start",&s.anchor,now,removal).await?;
 }
 tx.commit().await?;Ok(Json(json!({"ok":true})))
}
