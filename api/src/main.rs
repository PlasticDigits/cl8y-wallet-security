mod auth;
mod assignments;
mod notifications;
mod worker;
use axum::{extract::State,http::{HeaderMap,StatusCode,header},response::{IntoResponse,Response},routing::{get,post},Json,Router};
use serde_json::{json,Value};
use sqlx::{postgres::PgPoolOptions,PgPool,Row};
use std::{env,sync::Arc};
use tower_http::{services::{ServeDir,ServeFile},set_header::SetResponseHeaderLayer};

#[derive(Clone)]
pub struct App {pub db:PgPool,pub origin:String,pub chain_id:String,pub source_sha:String,pub contact_key:Arc<[u8;32]>}
pub struct Error(StatusCode,&'static str);
pub type Result<T>=std::result::Result<T,Error>;
impl Error {
 pub fn unauthorized()->Self{Self(StatusCode::UNAUTHORIZED,"authentication required")}
 pub fn forbidden()->Self{Self(StatusCode::FORBIDDEN,"request not authorized")}
 pub fn bad(msg:&'static str)->Self{Self(StatusCode::BAD_REQUEST,msg)}
 pub fn limited()->Self{Self(StatusCode::TOO_MANY_REQUESTS,"request limit reached; try later")}
}
impl From<sqlx::Error> for Error {fn from(_:sqlx::Error)->Self{Self(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable")}}
impl IntoResponse for Error {fn into_response(self)->Response{(self.0,Json(json!({"error":self.1}))).into_response()}}
impl App {pub fn chain(&self)->Value{json!({"status":"unavailable","chain_id":self.chain_id,"reason":"Verified contract deployment identities and reviewed ABI integration are not configured. Profile membership does not grant chain authority.","contracts":[]})}}
async fn health(State(app):State<App>)->Result<Json<Value>> {
 let migration:i64=sqlx::query_scalar("SELECT COALESCE(max(version),0) FROM _sqlx_migrations WHERE success").fetch_one(&app.db).await?;
 let server_time:chrono::DateTime<chrono::Utc>=sqlx::query_scalar("SELECT now()").fetch_one(&app.db).await?;
 Ok(Json(json!({"status":"ok","source_sha":app.source_sha,"migration":migration,"server_time":server_time})))
}
async fn status(State(app):State<App>)->Result<Json<Value>> {
 let heartbeat=sqlx::query("SELECT last_seen,source_sha,detail FROM worker_heartbeats WHERE name='notifications'").fetch_optional(&app.db).await?;
 let worker=heartbeat.map(|r|json!({"last_seen":r.get::<chrono::DateTime<chrono::Utc>,_>("last_seen"),"source_sha":r.get::<String,_>("source_sha"),"detail":r.get::<Value,_>("detail")}));
 Ok(Json(json!({"source_sha":app.source_sha,"chain":app.chain(),"notifications":{"delivery_enabled":false,"reason":"Live delivery requires explicit send authorization and provider configuration; no messages are sent."},"worker":worker})))
}
async fn me(State(app):State<App>,headers:HeaderMap)->Result<Json<Value>> {
 let s=match auth::session(&app,&headers).await {Ok(s)=>s,Err(Error(StatusCode::UNAUTHORIZED,_))=>return Ok(Json(json!({"authenticated":false,"wallets":[],"assignments":[],"contacts":[],"chain":app.chain()}))),Err(e)=>return Err(e)};
 let wallets=sqlx::query("SELECT address,verified_at FROM wallets WHERE profile_id=$1 ORDER BY verified_at").bind(s.profile_id).fetch_all(&app.db).await?.into_iter().map(|r|json!({"address":r.get::<String,_>("address"),"verified_at":r.get::<chrono::DateTime<chrono::Utc>,_>("verified_at")})).collect::<Vec<_>>();
 let assignments=assignments::list(&app,s.profile_id).await?;
 let contacts=notifications::list(&app,s.profile_id).await?;
 let server_time:chrono::DateTime<chrono::Utc>=sqlx::query_scalar("SELECT now()").fetch_one(&app.db).await?;
 Ok(Json(json!({"authenticated":true,"csrf_token":s.csrf,"profile_id":s.profile_id,"anchor_wallet":s.anchor,"wallets":wallets,"assignments":assignments,"contacts":contacts,"chain":app.chain(),"server_time":server_time})))
}
#[tokio::main]
async fn main()->anyhow::Result<()> {
 let origin=env::var("PUBLIC_ORIGIN")?;let parsed=reqwest::Url::parse(&origin)?;
 anyhow::ensure!(parsed.scheme()=="https"&&parsed.path()=="/"&&parsed.query().is_none()&&parsed.fragment().is_none()&&parsed.username().is_empty()&&parsed.password().is_none(),"PUBLIC_ORIGIN must be an HTTPS origin");
 let key=hex::decode(env::var("CONTACT_ENCRYPTION_KEY")?)?;let key:[u8;32]=key.try_into().map_err(|_|anyhow::anyhow!("invalid contact encryption key length"))?;
 let db=PgPoolOptions::new().max_connections(8).connect(&env::var("DATABASE_URL")?).await?;
 // Runtime role may use a distinct migration URL, supplied only to migration jobs.
 if env::var("RUN_MIGRATIONS").as_deref()==Ok("true") {sqlx::migrate!("./migrations").run(&db).await?;}
 let applied:i64=sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success").fetch_one(&db).await?;
 anyhow::ensure!(applied>=1,"migrations required");
 let app=App{db,origin:origin.trim_end_matches('/').into(),chain_id:env::var("CHAIN_ID").unwrap_or_else(|_|"columbus-5".into()),source_sha:env::var("SOURCE_SHA").unwrap_or_else(|_|"development".into()),contact_key:Arc::new(key)};
 let mode=env::var("PROCESS_MODE").unwrap_or_else(|_|"api".into());
 if mode=="worker" {return worker::run(app).await}
 let routes=Router::new().route("/healthz",get(health)).route("/api/v1/status",get(status)).route("/api/v1/me",get(me))
 .route("/api/v1/auth/challenge",post(auth::challenge)).route("/api/v1/auth/verify",post(auth::verify)).route("/api/v1/auth/logout",post(auth::logout))
 .route("/api/v1/assignments",post(assignments::propose)).route("/api/v1/assignments/{id}/cancel",post(assignments::cancel))
 .route("/api/v1/contacts/email",post(notifications::email)).route("/api/v1/contacts/email/verify",post(notifications::verify_email))
 .route("/api/v1/contacts/telegram",post(notifications::telegram)).route("/api/v1/contacts/{id}/remove",post(notifications::remove))
 .fallback_service(ServeDir::new(env::var("WEB_ROOT").unwrap_or_else(|_|"frontend/dist".into())).not_found_service(ServeFile::new(env::var("WEB_ROOT").unwrap_or_else(|_|"frontend/dist".into())+"/index.html")))
 .layer(axum::extract::DefaultBodyLimit::max(16384))
 .layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL,header::HeaderValue::from_static("no-store")))
 .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY,header::HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")))
 .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS,header::HeaderValue::from_static("nosniff")))
 .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY,header::HeaderValue::from_static("no-referrer")))
 .layer(SetResponseHeaderLayer::overriding(header::STRICT_TRANSPORT_SECURITY,header::HeaderValue::from_static("max-age=31536000")))
 .with_state(app);
 let listener=tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
 axum::serve(listener,routes).with_graceful_shutdown(async{let _=tokio::signal::ctrl_c().await;}).await?;Ok(())
}
