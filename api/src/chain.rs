//! ABI v1 adapter. All identities/endpoints originate from reviewed operator registry,
//! never HTTP request input. No signer or transaction broadcast exists in this service.
use crate::{auth, notifications, App, Error, Result};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{collections::BTreeMap, env};
use uuid::Uuid;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub address: String,
    pub code_id: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub rpc_url: String,
    pub lcd_url: String,
    pub controller: Contract,
    pub contracts: Vec<Contract>,
    pub abi_sha: String,
    pub start_height: i64,
    pub gas_price: Option<String>,
}
impl Registry {
    pub fn load() -> anyhow::Result<Option<Self>> {
        let Ok(raw) = env::var("CHAIN_REGISTRY_JSON") else {
            return Ok(None);
        };
        let cfg: Self = serde_json::from_str(&raw)?;
        for url in [&cfg.rpc_url, &cfg.lcd_url] {
            let u = reqwest::Url::parse(url)?;
            anyhow::ensure!(
                u.scheme() == "https"
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.query().is_none()
                    && u.fragment().is_none()
                    && u.path() == "/",
                "registry endpoint must be HTTPS origin"
            );
        }
        anyhow::ensure!(
            cfg.start_height > 0 && !cfg.contracts.is_empty() && cfg.contracts.len() <= 32,
            "invalid registry bounds"
        );
        anyhow::ensure!(
            cfg.abi_sha.len() == 40 && cfg.abi_sha.bytes().all(|b| b.is_ascii_hexdigit()),
            "reviewed ABI source SHA required"
        );
        for c in cfg.contracts.iter().chain(std::iter::once(&cfg.controller)) {
            anyhow::ensure!(
                auth::valid_address(&c.address) && c.code_id.parse::<u64>().is_ok_and(|n| n > 0),
                "invalid contract identity"
            );
        }
        Ok(Some(cfg))
    }
}
fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
async fn get_json(url: reqwest::Url, height: Option<i64>) -> anyhow::Result<Value> {
    let mut request = client()?.get(url);
    if let Some(h) = height {
        request = request.header("x-cosmos-block-height", h.to_string())
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("chain_transport_unavailable"))?;
    anyhow::ensure!(response.status().is_success(), "chain_query_rejected");
    if let Some(h) = height {
        anyhow::ensure!(
            response
                .headers()
                .get("x-cosmos-block-height")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<i64>().ok())
                == Some(h),
            "chain_height_not_pinned"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("chain_response_unavailable"))?
    {
        anyhow::ensure!(
            body.len() + chunk.len() <= 8 * 1024 * 1024,
            "chain_response_too_large"
        );
        body.extend(chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}
async fn rpc(cfg: &Registry, path: &str, height: Option<i64>) -> anyhow::Result<Value> {
    let mut url = reqwest::Url::parse(&cfg.rpc_url)?.join(path)?;
    if let Some(h) = height {
        url.query_pairs_mut().append_pair("height", &h.to_string());
    }
    let v = get_json(url, None).await?;
    anyhow::ensure!(v.get("error").is_none(), "rpc_error");
    Ok(v["result"].clone())
}
async fn smart(cfg: &Registry, contract: &str, msg: Value, height: i64) -> anyhow::Result<Value> {
    let mut url = reqwest::Url::parse(&cfg.lcd_url)?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid_lcd"))?
        .extend([
            "cosmwasm",
            "wasm",
            "v1",
            "contract",
            contract,
            "smart",
            &STANDARD.encode(serde_json::to_vec(&msg)?),
        ]);
    let v = get_json(url, Some(height)).await?;
    anyhow::ensure!(v.get("data").is_some(), "invalid_smart_response");
    Ok(v["data"].clone())
}
async fn contract_identity(cfg: &Registry, c: &Contract, height: i64) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(&cfg.lcd_url)?
        .join(&format!("cosmwasm/wasm/v1/contract/{}", c.address))?;
    let v = get_json(url, Some(height)).await?;
    let code = v["contract_info"]["code_id"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            v["contract_info"]["code_id"]
                .as_u64()
                .map(|v| v.to_string())
        });
    anyhow::ensure!(
        code.as_deref() == Some(c.code_id.as_str()),
        "contract_code_identity_mismatch"
    );
    Ok(())
}
async fn head(app: &App, cfg: &Registry) -> anyhow::Result<i64> {
    let status = rpc(cfg, "status", None).await?;
    anyhow::ensure!(
        status["node_info"]["network"].as_str() == Some(app.chain_id.as_str())
            && !status["sync_info"]["catching_up"].as_bool().unwrap_or(true),
        "chain_identity_or_sync_mismatch"
    );
    let h = status["sync_info"]["latest_block_height"]
        .as_str()
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid_height"))?;
    anyhow::ensure!(h > 2, "chain_not_ready");
    Ok(h - 2)
}
async fn validate(cfg: &Registry, height: i64) -> anyhow::Result<()> {
    contract_identity(cfg, &cfg.controller, height).await?;
    let controller = smart(cfg, &cfg.controller.address, json!({"config":{}}), height).await?;
    anyhow::ensure!(
        controller["interface_version"] == 1,
        "unsupported_controller_abi"
    );
    for token in &cfg.contracts {
        contract_identity(cfg, token, height).await?;
        let security = smart(cfg, &token.address, json!({"security_config":{}}), height).await?;
        anyhow::ensure!(
            security["controller"].as_str() == Some(cfg.controller.address.as_str()),
            "token_controller_mismatch"
        );
    }
    Ok(())
}
pub async fn status(app: &App) -> Value {
    let reason="Verified contract deployments, reviewed registry and finalized ingestion are not available.";
    let unavailable =
        || json!({"status":"unavailable","chain_id":app.chain_id,"reason":reason,"contracts":[]});
    let Ok(Some(cfg)) = Registry::load() else {
        return unavailable();
    };
    let Ok(Some(row))=sqlx::query("SELECT detail,last_seen>now()-interval '60 seconds' AS fresh FROM worker_heartbeats WHERE name='chain'").fetch_optional(&app.db).await else{return unavailable()};
    let detail: Value = row.get("detail");
    if !row.get::<bool, _>("fresh") || detail["status"] != "ready" {
        return unavailable();
    }
    json!({"status":"ready","chain_id":app.chain_id,"reason":"Verified configured contract identities; queries pinned to finalized chain height. Unlisted assets remain uncovered.","contracts":cfg.contracts.iter().map(|c|json!({"address":c.address,"code_id":c.code_id})).collect::<Vec<_>>(),"controller":cfg.controller.address,"abi_sha":cfg.abi_sha,"rpc_url":cfg.rpc_url,"lcd_url":cfg.lcd_url,"gas_price":cfg.gas_price,"indexed_height":detail["height"],"chain_time":detail["chain_time"]})
}
fn unavailable() -> Error {
    Error(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "authoritative chain state unavailable or unsupported; no action authorized",
    )
}
async fn context(app: &App, contract: &str) -> Result<(Registry, i64, DateTime<Utc>)> {
    let cfg = Registry::load()
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    if !cfg.contracts.iter().any(|c| c.address == contract) {
        return Err(unavailable());
    }
    let h = head(app, &cfg).await.map_err(|_| unavailable())?;
    validate(&cfg, h).await.map_err(|_| unavailable())?;
    let block = rpc(&cfg, "block", Some(h))
        .await
        .map_err(|_| unavailable())?;
    let time = block["block"]["header"]["time"]
        .as_str()
        .and_then(|v| v.parse::<DateTime<Utc>>().ok())
        .ok_or_else(unavailable)?;
    Ok((cfg, h, time))
}
pub async fn wallet(
    State(app): State<App>,
    headers: HeaderMap,
    Path((contract, wallet)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let s = auth::session(&app, &headers).await?;
    let own: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM wallets WHERE profile_id=$1 AND address=$2)",
    )
    .bind(s.profile_id)
    .bind(&wallet)
    .fetch_one(&app.db)
    .await?;
    if !own {
        return Err(Error::forbidden());
    }
    let (cfg, h, time) = context(&app, &contract).await?;
    let (state, guard, info, balance) = tokio::try_join!(
        smart(
            &cfg,
            &contract,
            json!({"wallet_security":{"address":wallet}}),
            h
        ),
        smart(
            &cfg,
            &cfg.controller.address,
            json!({"guard":{"token":contract,"addresses":[wallet]}}),
            h
        ),
        smart(&cfg, &contract, json!({"token_info":{}}), h),
        smart(&cfg, &contract, json!({"balance":{"address":wallet}}), h)
    )
    .map_err(|_| unavailable())?;
    if guard["interface_version"] != 1 || guard["blocked"].as_array().is_none_or(|v| v.len() != 1) {
        return Err(unavailable());
    }
    Ok(Json(
        json!({"chain_id":app.chain_id,"contract":contract,"controller":cfg.controller.address,"chain_time":time,"height":h.to_string(),"wallet_security":state,"guard":guard,"token_info":info,"balance":balance}),
    ))
}
pub async fn recovery(
    State(app): State<App>,
    headers: HeaderMap,
    Path((contract, nonce)): Path<(String, String)>,
) -> Result<Json<Value>> {
    auth::session(&app, &headers).await?;
    if nonce.parse::<u64>().is_err() {
        return Err(Error::bad("invalid nonce"));
    }
    let (cfg, h, time) = context(&app, &contract).await?;
    let recovery = smart(
        &cfg,
        &contract,
        json!({"recovery":{"nonce":nonce.parse::<u64>().map_err(|_|Error::bad("invalid nonce"))?}}),
        h,
    )
    .await
    .map_err(|_| unavailable())?;
    Ok(Json(
        json!({"chain_id":app.chain_id,"contract":contract,"chain_time":time,"height":h.to_string(),"recovery":recovery}),
    ))
}
fn attributes(event: &Value) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for a in event["attributes"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid_event_attributes"))?
    {
        let k = a["key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid_attribute_key"))?;
        let v = a["value"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid_attribute_value"))?;
        // Tendermint0.34 RPC encodes both fields; Comet0.38 emits plaintext.
        let decoded = STANDARD
            .decode(k)
            .ok()
            .and_then(|b| String::from_utf8(b).ok());
        let (key, value) = if decoded.as_ref().is_some_and(|s| {
            [
                "_contract_address",
                "action",
                "nonce",
                "token",
                "wallet",
                "source",
                "destination",
                "initiator",
                "proposed_at",
                "executable_at",
            ]
            .contains(&s.as_str())
        }) {
            (decoded.unwrap(), String::from_utf8(STANDARD.decode(v)?)?)
        } else {
            (k.into(), v.into())
        };
        if ![
            "_contract_address",
            "action",
            "nonce",
            "token",
            "wallet",
            "source",
            "destination",
            "initiator",
            "proposed_at",
            "executable_at",
        ]
        .contains(&key.as_str())
        {
            continue;
        }
        anyhow::ensure!(
            out.insert(key, value).is_none(),
            "ambiguous_event_attribute"
        );
    }
    Ok(out)
}
const TIMER_ACTIONS: [&str; 6] = [
    "schedule_wallet_change",
    "schedule_assignment",
    "propose_recovery",
    "propose_role",
    "propose_rotation_delay",
    "propose_blacklist_clear",
];
async fn ingest(app: &App, cfg: &Registry) -> anyhow::Result<(i64, DateTime<Utc>)> {
    let latest = head(app, cfg).await?;
    validate(cfg, latest).await?;
    let mut tx = app.db.begin().await?;
    if !sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(811205994)")
        .fetch_one(&mut *tx)
        .await?
    {
        return Err(anyhow::anyhow!("ingestion_leader_busy"));
    }
    let checkpoint =
        sqlx::query("SELECT height,block_hash FROM chain_checkpoints WHERE chain_id=$1 FOR UPDATE")
            .bind(&app.chain_id)
            .fetch_optional(&mut *tx)
            .await?;
    let (mut height, mut previous) = if let Some(row) = checkpoint {
        (
            row.get::<i64, _>("height"),
            row.get::<String, _>("block_hash"),
        )
    } else {
        let h = cfg.start_height - 1;
        let hash = if h > 0 {
            rpc(cfg, "block", Some(h)).await?["block_id"]["hash"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid_checkpoint_block"))?
                .to_owned()
        } else {
            String::new()
        };
        (h, hash)
    };
    anyhow::ensure!(height <= latest, "finalized_height_regressed");
    // Revalidate the last checkpoint identity before advancing; finalized divergence halts
    // instead of replaying already-sent warnings or rolling back protections silently.
    if height > 0 {
        let last = rpc(cfg, "block", Some(height)).await?;
        anyhow::ensure!(
            last["block_id"]["hash"].as_str() == Some(previous.as_str()),
            "finalized_checkpoint_divergence"
        );
    }
    let mut time = None;
    for h in (height + 1)..=latest.min(height + 5) {
        let (block, results) = tokio::try_join!(
            rpc(cfg, "block", Some(h)),
            rpc(cfg, "block_results", Some(h))
        )?;
        anyhow::ensure!(
            block["block"]["header"]["chain_id"].as_str() == Some(app.chain_id.as_str())
                && block["block"]["header"]["height"].as_str() == Some(h.to_string().as_str()),
            "receipt_chain_height_mismatch"
        );
        if h > 1 {
            anyhow::ensure!(
                block["block"]["header"]["last_block_id"]["hash"].as_str()
                    == Some(previous.as_str()),
                "finalized_parent_divergence"
            );
        }
        let block_time: DateTime<Utc> = block["block"]["header"]["time"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing_block_time"))?
            .parse()?;
        let empty = vec![];
        let txs = block["block"]["data"]["txs"].as_array().unwrap_or(&empty);
        let receipts = results["txs_results"].as_array().unwrap_or(&empty);
        anyhow::ensure!(txs.len() == receipts.len(), "receipt_count_mismatch");
        for (txindex, result) in receipts.iter().enumerate() {
            if result["code"].as_u64().unwrap_or(0) != 0 {
                continue;
            }
            let hash = hex::encode_upper(Sha256::digest(
                STANDARD.decode(
                    txs[txindex]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("invalid_tx_bytes"))?,
                )?,
            ));
            for (index, event) in result["events"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .enumerate()
            {
                if event["type"] != "wasm" {
                    continue;
                }
                // Host-added emitting identity is first; untrusted contracts cannot make
                // arbitrary ordinary attributes poison every later finalized checkpoint.
                let emitter = event["attributes"].as_array().and_then(|attrs| {
                    attrs.iter().find_map(|a| {
                        let key = a["key"].as_str()?;
                        if key == "_contract_address" {
                            return a["value"].as_str().map(str::to_owned);
                        }
                        if STANDARD.decode(key).ok()?.as_slice() == b"_contract_address" {
                            return String::from_utf8(STANDARD.decode(a["value"].as_str()?).ok()?)
                                .ok();
                        }
                        None
                    })
                });
                if !emitter.as_ref().is_some_and(|c| {
                    c == &cfg.controller.address || cfg.contracts.iter().any(|t| &t.address == c)
                }) {
                    continue;
                }
                let attrs = attributes(event)?;
                let Some(contract) = attrs.get("_contract_address") else {
                    continue;
                };
                let controller = contract == &cfg.controller.address;
                if !controller && !cfg.contracts.iter().any(|c| &c.address == contract) {
                    continue;
                }
                let Some(action) = attrs
                    .get("action")
                    .filter(|a| TIMER_ACTIONS.contains(&a.as_str()))
                else {
                    continue;
                };
                let nonce = attrs
                    .get("nonce")
                    .ok_or_else(|| anyhow::anyhow!("missing_timer_nonce"))?;
                let _ = nonce.parse::<u64>()?;
                let start = DateTime::from_timestamp(
                    attrs
                        .get("proposed_at")
                        .ok_or_else(|| anyhow::anyhow!("missing_timer_start"))?
                        .parse()?,
                    0,
                )
                .ok_or_else(|| anyhow::anyhow!("invalid_timer_start"))?;
                let end = DateTime::from_timestamp(
                    attrs
                        .get("executable_at")
                        .ok_or_else(|| anyhow::anyhow!("missing_timer_deadline"))?
                        .parse()?,
                    0,
                )
                .ok_or_else(|| anyhow::anyhow!("invalid_timer_deadline"))?;
                anyhow::ensure!(
                    start.timestamp() == block_time.timestamp() && end >= start,
                    "timer_receipt_time_mismatch"
                );
                let affected = attrs
                    .get("wallet")
                    .or_else(|| attrs.get("source"))
                    .cloned()
                    .unwrap_or_else(|| contract.clone());
                if !controller {
                    anyhow::ensure!(attrs.get("token") == Some(contract), "timer_token_mismatch");
                }
                let semantic = format!("{}:{contract}:{action}:{affected}:{nonce}", app.chain_id);
                let inserted=sqlx::query("INSERT INTO chain_receipts(chain_id,height,tx_hash,event_index,contract,semantic_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
     .bind(&app.chain_id).bind(h).bind(&hash).bind(index as i32).bind(contract).bind(&semantic).execute(&mut *tx).await?;
                if inserted.rows_affected() == 0 {
                    continue;
                }
                if controller {
                    sqlx::query("INSERT INTO security_events(id,action,wallet,token,proposed_at,executable_at,chain_id,block_height,tx_hash,event_index) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING")
                    .bind(&semantic).bind(action).bind(&affected).bind(contract).bind(start).bind(end).bind(&app.chain_id).bind(h).bind(&hash).bind(index as i32).execute(&mut *tx).await?;
                    sqlx::query(
                        "INSERT INTO controller_fanout(event_id) VALUES($1) ON CONFLICT DO NOTHING",
                    )
                    .bind(&semantic)
                    .execute(&mut *tx)
                    .await?;
                    continue;
                }
                let profiles: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT DISTINCT profile_id FROM wallets WHERE address=$1 OR address=$2",
                )
                .bind(&affected)
                .bind(attrs.get("destination"))
                .fetch_all(&mut *tx)
                .await?;
                for profile in profiles {
                    let id = format!("{semantic}:{profile}");
                    notifications::record(&mut tx, &id, profile, action, &affected, start, end)
                        .await
                        .map_err(|_| anyhow::anyhow!("outbox_storage_unavailable"))?;
                    sqlx::query("UPDATE security_events SET token=$2,chain_id=$3,block_height=$4,tx_hash=$5,event_index=$6 WHERE id=$1").bind(id).bind(contract).bind(&app.chain_id).bind(h).bind(&hash).bind(index as i32).execute(&mut *tx).await?;
                }
            }
        }
        height = h;
        previous = block["block_id"]["hash"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing_block_hash"))?
            .to_owned();
        time = Some(block_time);
        sqlx::query("INSERT INTO chain_checkpoints(chain_id,height,block_hash) VALUES($1,$2,$3) ON CONFLICT(chain_id) DO UPDATE SET height=EXCLUDED.height,block_hash=EXCLUDED.block_hash,updated_at=now()")
   .bind(&app.chain_id).bind(height).bind(&previous).execute(&mut *tx).await?;
    }
    let time = if let Some(t) = time {
        t
    } else {
        rpc(cfg, "block", Some(height)).await?["block"]["header"]["time"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing_block_time"))?
            .parse()?
    };
    tx.commit().await?;
    Ok((height, time))
}
pub async fn fanout(app: &App) -> anyhow::Result<()> {
    let mut tx = app.db.begin().await?;
    let jobs=sqlx::query("SELECT f.event_id,f.cursor,e.proposed_at FROM controller_fanout f JOIN security_events e ON e.id=f.event_id WHERE f.completed_at IS NULL ORDER BY f.created_at LIMIT 5 FOR UPDATE OF f SKIP LOCKED").fetch_all(&mut *tx).await?;
    for job in jobs {
        let id: String = job.get("event_id");
        let cursor: Option<Uuid> = job.get("cursor");
        let start: DateTime<Utc> = job.get("proposed_at");
        let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM contacts WHERE ($1::uuid IS NULL OR id>$1) AND verified_at<=$2 AND (activation_at IS NULL OR activation_at<=$2) AND (removal_at IS NULL OR removal_at>$2) AND deleted_at IS NULL ORDER BY id LIMIT 100")
   .bind(cursor).bind(start).fetch_all(&mut *tx).await?;
        for contact in &ids {
            sqlx::query("INSERT INTO notification_outbox(id,event_id,contact_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(&id).bind(contact).execute(&mut *tx).await?;
        }
        if let Some(last) = ids.last() {
            sqlx::query("UPDATE controller_fanout SET cursor=$2 WHERE event_id=$1")
                .bind(&id)
                .bind(last)
                .execute(&mut *tx)
                .await?;
        }
        if ids.len() < 100 {
            sqlx::query("UPDATE controller_fanout SET completed_at=now() WHERE event_id=$1")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
pub async fn run(app: App) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        let result = async {
            let cfg = Registry::load()?.ok_or_else(|| anyhow::anyhow!("registry_unconfigured"))?;
            ingest(&app, &cfg).await
        };
        let detail = match tokio::time::timeout(std::time::Duration::from_secs(40), result).await {
            Ok(Ok((height, time))) => {
                json!({"status":"ready","height":height.to_string(),"chain_time":time})
            }
            _ => {
                json!({"status":"unavailable","reason":"Registry, finalized receipts or contract identities unavailable; checkpoint retained."})
            }
        };
        let _=sqlx::query("INSERT INTO worker_heartbeats(name,last_seen,source_sha,detail) VALUES('chain',now(),$1,$2) ON CONFLICT(name) DO UPDATE SET last_seen=now(),source_sha=EXCLUDED.source_sha,detail=EXCLUDED.detail").bind(&app.source_sha).bind(detail).execute(&app.db).await;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_rpc_attribute_formats() {
        for encoded in [false, true] {
            let attrs = [
                ("_contract_address", "terra1example"),
                ("action", "schedule_wallet_change"),
                ("nonce", "7"),
            ]
            .iter()
            .map(|(k, v)| {
                if encoded {
                    json!({"key":STANDARD.encode(k),"value":STANDARD.encode(v)})
                } else {
                    json!({"key":k,"value":v})
                }
            })
            .collect::<Vec<_>>();
            let parsed = attributes(&json!({"attributes":attrs})).unwrap();
            assert_eq!(parsed["nonce"], "7");
            assert_eq!(parsed["action"], "schedule_wallet_change");
        }
    }
    #[test]
    fn ambiguous_contract_attributes_rejected() {
        assert!(attributes(&json!({"attributes":[{"key":"_contract_address","value":"a"},{"key":"_contract_address","value":"b"}]})).is_err());
    }
}
#[cfg(test)]
pub(crate) async fn fixture_ingestion(app: &App, source: &str) -> anyhow::Result<()> {
    use axum::{http::Uri, routing::get, Router};
    let token = source.to_owned();
    let controller = "terra1controller-fixture".to_owned();
    let sample = json!({"token":token,"controller":controller});
    let handler = move |headers: HeaderMap, uri: Uri| {
        let sample = sample.clone();
        async move {
            let height = uri
                .query()
                .and_then(|v| v.strip_prefix("height="))
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(10);
            let path = uri.path();
            let time = "2026-10-31T00:00:00Z";
            let event = json!({"type":"wasm","attributes":[{"key":"_contract_address","value":sample["token"]},{"key":"action","value":"schedule_wallet_change"},{"key":"nonce","value":"77"},{"key":"token","value":sample["token"]},{"key":"wallet","value":sample["token"]},{"key":"proposed_at","value":"1793404800"},{"key":"executable_at","value":"1793491200"}]});
            let value = if path == "/status" {
                json!({"result":{"node_info":{"network":"columbus-5"},"sync_info":{"catching_up":false,"latest_block_height":"12"}}})
            } else if path == "/block" {
                json!({"result":{"block_id":{"hash":format!("hash{height}")},"block":{"header":{"chain_id":"columbus-5","height":height.to_string(),"time":time,"last_block_id":{"hash":format!("hash{}",height-1)}},"data":{"txs":[STANDARD.encode("owned synthetic tx")]}}}})
            } else if path == "/block_results" {
                json!({"result":{"txs_results":[{"code":0,"events":[{"type":"wasm","attributes":[{"key":"_contract_address","value":"unallowlisted-permissionless-contract"},{"key":"action","value":"noise"},{"key":"action","value":"noise-duplicate"}]},event]}]}})
            } else if path.contains("/smart/") {
                if path.contains(sample["controller"].as_str().unwrap()) {
                    json!({"data":{"interface_version":1}})
                } else {
                    json!({"data":{"controller":sample["controller"]}})
                }
            } else {
                json!({"contract_info":{"code_id":if path.contains(sample["controller"].as_str().unwrap()){"72"}else{"71"}}})
            };
            let mut out = HeaderMap::new();
            if let Some(h) = headers.get("x-cosmos-block-height") {
                out.insert("x-cosmos-block-height", h.clone());
            }
            (out, Json(value))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(get(handler)))
            .await
            .unwrap()
    });
    let cfg = Registry {
        rpc_url: format!("http://127.0.0.1:{port}/"),
        lcd_url: format!("http://127.0.0.1:{port}/"),
        controller: Contract {
            address: controller,
            code_id: "72".into(),
        },
        contracts: vec![Contract {
            address: source.into(),
            code_id: "71".into(),
        }],
        abi_sha: "a".repeat(40),
        start_height: 10,
        gas_price: None,
    };
    // HTTP only in this owned test fixture; production Registry::load requires HTTPS.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM chain_receipts WHERE chain_id=$1")
        .bind(&app.chain_id)
        .fetch_one(&app.db)
        .await?;
    let (h, _) = ingest(app, &cfg).await?;
    assert_eq!(h, 10);
    ingest(app, &cfg).await?;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM chain_receipts WHERE chain_id=$1")
        .bind(&app.chain_id)
        .fetch_one(&app.db)
        .await?;
    assert_eq!(after, before + 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE chain_id=$1 AND tx_hash IS NOT NULL",
    )
    .bind(&app.chain_id)
    .fetch_one(&app.db)
    .await?;
    assert!(count >= 1);
    sqlx::query("UPDATE chain_checkpoints SET block_hash='divergent' WHERE chain_id=$1")
        .bind(&app.chain_id)
        .execute(&app.db)
        .await?;
    assert!(ingest(app, &cfg).await.is_err());
    // Fixture owns only its checkpoint; restore it so later runs can exercise the same replay case.
    sqlx::query("DELETE FROM chain_checkpoints WHERE chain_id=$1")
        .bind(&app.chain_id)
        .execute(&app.db)
        .await?;
    sqlx::query("DELETE FROM notification_outbox WHERE event_id IN(SELECT id FROM security_events WHERE chain_id=$1)").bind(&app.chain_id).execute(&app.db).await?;
    sqlx::query("DELETE FROM security_events WHERE chain_id=$1")
        .bind(&app.chain_id)
        .execute(&app.db)
        .await?;
    sqlx::query("DELETE FROM chain_receipts WHERE chain_id=$1")
        .bind(&app.chain_id)
        .execute(&app.db)
        .await?;
    server.abort();
    Ok(())
}
