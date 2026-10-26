use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Request, Response, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use chrono::Utc;
use rand::Rng;
use reqwest::Client;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::Path as FsPath,
    sync::{Arc, Mutex},
    time::Instant,
};
use thiserror::Error;

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:18766";

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("数据库错误：{0}")]
    Database(#[from] rusqlite::Error),
    #[error("网络请求失败：{0}")]
    Request(#[from] reqwest::Error),
    #[error("渠道不存在")]
    NotFound,
    #[error("没有可用于模型 {0} 的渠道")]
    NoChannel(String),
    #[error("网关启动失败：{0}")]
    Server(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Channel {
    pub id: i64,
    pub name: String,
    pub base_url: String,
    pub api_key: String,
    pub protocol: String,
    pub models: Vec<String>,
    pub priority: i64,
    pub weight: u32,
    pub enabled: bool,
    pub available: bool,
    pub consecutive_failures: u32,
    pub latency_ms: Option<u64>,
    pub last_test_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInput {
    pub id: Option<i64>,
    pub name: String,
    pub base_url: String,
    pub api_key: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_weight() -> u32 {
    100
}
fn default_protocol() -> String {
    "openai".into()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelTestResult {
    pub success: bool,
    pub latency_ms: u64,
    pub message: String,
    pub model: String,
}

#[derive(Clone)]
pub struct Gateway {
    connection: Arc<Mutex<Connection>>,
    client: Client,
}

impl Gateway {
    pub fn open(path: impl AsRef<FsPath>) -> Result<Self, GatewayError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS gateway_channels (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL,
               base_url TEXT NOT NULL,
               api_key TEXT NOT NULL,
               protocol TEXT NOT NULL DEFAULT 'openai',
               models TEXT NOT NULL DEFAULT '[]',
               priority INTEGER NOT NULL DEFAULT 0,
               weight INTEGER NOT NULL DEFAULT 100,
               enabled INTEGER NOT NULL DEFAULT 1,
               available INTEGER NOT NULL DEFAULT 1,
               consecutive_failures INTEGER NOT NULL DEFAULT 0,
               latency_ms INTEGER,
               last_test_at TEXT,
               last_error TEXT
             );",
        )?;
        let has_protocol = connection
            .prepare("PRAGMA table_info(gateway_channels)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == "protocol");
        if !has_protocol {
            connection.execute(
                "ALTER TABLE gateway_channels ADD COLUMN protocol TEXT NOT NULL DEFAULT 'openai'",
                [],
            )?;
        }
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            client,
        })
    }

    pub fn list_channels(&self) -> Result<Vec<Channel>, GatewayError> {
        let connection = self.connection.lock().expect("gateway database lock");
        let mut statement = connection.prepare("SELECT id,name,base_url,api_key,protocol,models,priority,weight,enabled,available,consecutive_failures,latency_ms,last_test_at,last_error FROM gateway_channels ORDER BY priority DESC,id ASC")?;
        let rows = statement
            .query_map([], row_to_channel)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn save_channel(&self, input: ChannelInput) -> Result<Channel, GatewayError> {
        if input.name.trim().is_empty()
            || input.base_url.trim().is_empty()
            || input.api_key.trim().is_empty()
        {
            return Err(GatewayError::Server("渠道名称、地址和密钥不能为空".into()));
        }
        let models =
            serde_json::to_string(&normalize_models(input.models)).unwrap_or_else(|_| "[]".into());
        let base_url = input.base_url.trim().trim_end_matches('/').to_string();
        let protocol = normalize_protocol(&input.protocol);
        let connection = self.connection.lock().expect("gateway database lock");
        let id = if let Some(id) = input.id {
            connection.execute("UPDATE gateway_channels SET name=?,base_url=?,api_key=?,protocol=?,models=?,priority=?,weight=?,enabled=?,available=CASE WHEN enabled<>? THEN 1 ELSE available END WHERE id=?", params![input.name.trim(),base_url,input.api_key.trim(),protocol,models,input.priority,input.weight,input.enabled,input.enabled,id])?;
            id
        } else {
            connection.execute("INSERT INTO gateway_channels(name,base_url,api_key,protocol,models,priority,weight,enabled) VALUES(?,?,?,?,?,?,?,?)", params![input.name.trim(),base_url,input.api_key.trim(),protocol,models,input.priority,input.weight,input.enabled])?;
            connection.last_insert_rowid()
        };
        query_channel(&connection, id)?.ok_or(GatewayError::NotFound)
    }

    pub fn delete_channel(&self, id: i64) -> Result<(), GatewayError> {
        self.connection
            .lock()
            .expect("gateway database lock")
            .execute("DELETE FROM gateway_channels WHERE id=?", [id])?;
        Ok(())
    }

    pub async fn test_channel(
        &self,
        id: i64,
        model: String,
    ) -> Result<ChannelTestResult, GatewayError> {
        let channel = {
            let connection = self.connection.lock().expect("gateway database lock");
            query_channel(&connection, id)?.ok_or(GatewayError::NotFound)?
        };
        let model = if model.trim().is_empty() {
            channel
                .models
                .first()
                .cloned()
                .unwrap_or_else(|| "gpt-4o-mini".into())
        } else {
            model.trim().into()
        };
        let started = Instant::now();
        let test_body=serde_json::to_vec(&serde_json::json!({"model":model,"messages":[{"role":"user","content":"只回复：测试成功"}],"max_tokens":8,"stream":false})).unwrap_or_default();
        let prepared = prepare_upstream(&channel, "chat/completions", &test_body);
        let mut request = self
            .client
            .post(prepared.url)
            .body(prepared.body)
            .header("content-type", "application/json");
        for (name, value) in prepared.headers {
            request = request.header(name, value);
        }
        let result = request.send().await;
        let latency_ms = started.elapsed().as_millis() as u64;
        let (success, message) = match result {
            Ok(response) if response.status().is_success() => (
                true,
                format!("连接成功，状态码 {}", response.status().as_u16()),
            ),
            Ok(response) => (
                false,
                format!(
                    "上游返回状态码 {}：{}",
                    response.status().as_u16(),
                    response
                        .text()
                        .await
                        .unwrap_or_default()
                        .chars()
                        .take(300)
                        .collect::<String>()
                ),
            ),
            Err(error) => (false, error.to_string()),
        };
        self.record_health(
            id,
            success,
            latency_ms,
            if success { None } else { Some(&message) },
        )?;
        Ok(ChannelTestResult {
            success,
            latency_ms,
            message,
            model,
        })
    }

    pub async fn fetch_channel_models(&self, id: i64) -> Result<Vec<String>, GatewayError> {
        let channel = {
            let connection = self.connection.lock().expect("gateway database lock");
            query_channel(&connection, id)?.ok_or(GatewayError::NotFound)?
        };
        self.fetch_models_for_channel(&channel).await
    }

    pub async fn fetch_models_for_input(&self, input: &ChannelInput) -> Result<Vec<String>, GatewayError> {
        if input.base_url.trim().is_empty() || input.api_key.trim().is_empty() {
            return Err(GatewayError::Server("请先填写基础地址和 API 密钥".into()));
        }
        let channel = Channel { id: 0, name: input.name.clone(), base_url: input.base_url.trim().trim_end_matches('/').into(), api_key: input.api_key.clone(), protocol: normalize_protocol(&input.protocol), models: vec![], priority: input.priority, weight: input.weight, enabled: input.enabled, available: true, consecutive_failures: 0, latency_ms: None, last_test_at: None, last_error: None };
        self.fetch_models_for_channel(&channel).await
    }

    async fn fetch_models_for_channel(&self, channel: &Channel) -> Result<Vec<String>, GatewayError> {
        let url = match channel.protocol.as_str() {
            "anthropic" => upstream_url(&channel.base_url, "models"),
            "gemini" => format!(
                "{}/v1beta/models?key={}",
                channel.base_url.trim_end_matches('/'),
                channel.api_key
            ),
            _ => upstream_url(&channel.base_url, "models"),
        };
        let mut request = self.client.get(url).header("accept", "application/json");
        if channel.protocol == "anthropic" {
            request = request
                .header("x-api-key", &channel.api_key)
                .header("anthropic-version", "2023-06-01");
        } else if channel.protocol == "openai" {
            request = request.bearer_auth(&channel.api_key);
        }
        let response = request.send().await?.error_for_status()?;
        let value = response.json::<serde_json::Value>().await?;
        let mut models = if channel.protocol == "gemini" {
            value
                .get("models")
                .and_then(|item| item.as_array())
                .into_iter()
                .flatten()
                .filter_map(|item| {
                    item.get("name")
                        .and_then(|name| name.as_str())
                        .map(|name| name.trim_start_matches("models/").to_string())
                })
                .collect::<Vec<_>>()
        } else {
            value
                .get("data")
                .and_then(|item| item.as_array())
                .into_iter()
                .flatten()
                .filter_map(|item| {
                    item.get("id")
                        .and_then(|id| id.as_str())
                        .map(str::to_string)
                })
                .collect::<Vec<_>>()
        };
        models.sort();
        models.dedup();
        Ok(models)
    }

    pub async fn serve(self, address: &str) -> Result<(), GatewayError> {
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|error| GatewayError::Server(error.to_string()))?;
        let app = Router::new()
            .route("/v1/models", any(list_gateway_models))
            .route("/v1/{*path}", any(proxy_request))
            .route("/v1beta/{*path}", any(proxy_request))
            .route("/health", any(|| async { "AIGuard 网关运行正常" }))
            .with_state(self);
        axum::serve(listener, app)
            .await
            .map_err(|error| GatewayError::Server(error.to_string()))
    }

    pub async fn recover_unavailable_channels(&self) {
        let channels = self
            .list_channels()
            .unwrap_or_default()
            .into_iter()
            .filter(|channel| channel.enabled && !channel.available)
            .collect::<Vec<_>>();
        for channel in channels {
            let model = channel.models.first().cloned().unwrap_or_default();
            let _ = self.test_channel(channel.id, model).await;
        }
    }

    fn candidates(&self, model: &str) -> Result<Vec<Channel>, GatewayError> {
        let channels = self
            .list_channels()?
            .into_iter()
            .filter(|channel| {
                channel.enabled && channel.available && supports_model(channel, model)
            })
            .collect::<Vec<_>>();
        Ok(weighted_priority_order(channels))
    }

    fn record_health(
        &self,
        id: i64,
        success: bool,
        latency_ms: u64,
        error: Option<&str>,
    ) -> Result<(), GatewayError> {
        let connection = self.connection.lock().expect("gateway database lock");
        if success {
            connection.execute("UPDATE gateway_channels SET available=1,consecutive_failures=0,latency_ms=?,last_test_at=?,last_error=NULL WHERE id=?", params![latency_ms,Utc::now().to_rfc3339(),id])?;
        } else {
            connection.execute("UPDATE gateway_channels SET consecutive_failures=consecutive_failures+1,available=0,latency_ms=?,last_test_at=?,last_error=? WHERE id=?", params![latency_ms,Utc::now().to_rfc3339(),error,id])?;
        }
        Ok(())
    }
}

async fn list_gateway_models(State(gateway): State<Gateway>) -> impl IntoResponse {
    let mut models = gateway
        .list_channels()
        .unwrap_or_default()
        .into_iter()
        .filter(|channel| channel.enabled && channel.available)
        .flat_map(|channel| channel.models)
        .filter(|model| model != "*")
        .collect::<Vec<_>>();
    models.sort();
    models.dedup();
    let data = models
        .into_iter()
        .map(|id| serde_json::json!({"id":id,"object":"model","owned_by":"aiguard"}))
        .collect::<Vec<_>>();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(
            serde_json::json!({"object":"list","data":data}).to_string(),
        ))
        .expect("valid models response")
}

async fn proxy_request(
    State(gateway): State<Gateway>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    match proxy_inner(gateway, path, request).await {
        Ok(response) => response,
        Err(error) => json_error(StatusCode::BAD_GATEWAY, &error.to_string()),
    }
}

async fn proxy_inner(
    gateway: Gateway,
    path: String,
    request: Request<Body>,
) -> Result<Response<Body>, GatewayError> {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 32 * 1024 * 1024)
        .await
        .map_err(|error| GatewayError::Server(error.to_string()))?;
    let (canonical_path, inbound_protocol, canonical_body) =
        normalize_inbound_request(&path, &bytes);
    let model = serde_json::from_slice::<serde_json::Value>(&canonical_body)
        .ok()
        .and_then(|value| {
            value
                .get("model")
                .and_then(|item| item.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let candidates = gateway.candidates(&model)?;
    if candidates.is_empty() {
        return Err(GatewayError::NoChannel(model));
    }
    let mut last_error = String::new();
    for channel in candidates {
        let started = Instant::now();
        let prepared = prepare_upstream(&channel, &canonical_path, &canonical_body);
        let mut builder = gateway
            .client
            .request(parts.method.clone(), &prepared.url)
            .body(prepared.body.clone());
        for (name, value) in &prepared.headers {
            builder = builder.header(*name, value);
        }
        builder = copy_headers(builder, &parts.headers);
        match builder.send().await {
            Ok(response)
                if response.status().is_server_error()
                    || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || response.status() == reqwest::StatusCode::REQUEST_TIMEOUT =>
            {
                let status = response.status();
                let detail = response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(240)
                    .collect::<String>();
                last_error = format!("{} 返回状态码 {}：{}", channel.name, status, detail);
                gateway.record_health(
                    channel.id,
                    false,
                    started.elapsed().as_millis() as u64,
                    Some(&last_error),
                )?;
            }
            Ok(response) => {
                let status = response.status();
                let headers = response.headers().clone();
                gateway.record_health(
                    channel.id,
                    status.is_success(),
                    started.elapsed().as_millis() as u64,
                    None,
                )?;
                if prepared.adapted || inbound_protocol != "openai" {
                    let value = response
                        .json::<serde_json::Value>()
                        .await
                        .map_err(GatewayError::Request)?;
                    let adapted = adapt_response(&channel, value, &model);
                    let adapted = adapt_inbound_response(&inbound_protocol, adapted, &model);
                    let (body, content_type) =
                        adapted_response_body(&adapted, prepared.stream_requested);
                    return Ok(Response::builder()
                        .status(status)
                        .header("content-type", content_type)
                        .body(Body::from(body))
                        .expect("valid adapted response"));
                }
                let mut output = Response::builder().status(status);
                for (name, value) in &headers {
                    if name != reqwest::header::CONTENT_LENGTH
                        && name != reqwest::header::CONNECTION
                    {
                        output = output.header(name, value);
                    }
                }
                return Ok(output
                    .body(Body::from_stream(response.bytes_stream()))
                    .expect("valid upstream response"));
            }
            Err(error) => {
                last_error = format!("{}：{}", channel.name, error);
                gateway.record_health(
                    channel.id,
                    false,
                    started.elapsed().as_millis() as u64,
                    Some(&last_error),
                )?;
            }
        }
    }
    Err(GatewayError::Server(last_error))
}

fn normalize_inbound_request(path: &str, body: &[u8]) -> (String, String, Vec<u8>) {
    let path_without_query = path.split('?').next().unwrap_or(path);
    let value = serde_json::from_slice::<serde_json::Value>(body).unwrap_or_default();
    if path_without_query == "messages" {
        let mut messages = Vec::new();
        if let Some(rows) = value.get("messages").and_then(|item| item.as_array()) {
            for message in rows {
                messages.push(serde_json::json!({
                    "role": message.get("role").cloned().unwrap_or_else(|| serde_json::json!("user")),
                    "content": message_text(message.get("content")),
                }));
            }
        }
        let mut messages_with_system = messages;
        if let Some(system) = value.get("system") {
            let text = message_text(Some(system));
            if !text.is_empty() {
                messages_with_system.insert(0, serde_json::json!({"role":"system","content":text}));
            }
        }
        let canonical = serde_json::json!({
            "model": value.get("model").cloned().unwrap_or_default(),
            "messages": messages_with_system,
            "max_tokens": value.get("max_tokens").cloned().unwrap_or_else(|| serde_json::json!(1024)),
            "temperature": value.get("temperature").cloned().unwrap_or_else(|| serde_json::json!(1)),
            "stream": false,
        });
        return (
            "chat/completions".into(),
            "anthropic".into(),
            serde_json::to_vec(&canonical).unwrap_or_default(),
        );
    }
    if path_without_query.contains(":generateContent") {
        let model = path_without_query
            .split("/models/")
            .nth(1)
            .and_then(|part| part.split(':').next())
            .unwrap_or_default();
        let contents = value
            .get("contents")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        let canonical_messages = contents.as_array().map(|rows| rows.iter().map(|row| serde_json::json!({"role":if row.get("role").and_then(|item|item.as_str())==Some("model"){ "assistant" } else { "user" },"content":message_text(row.get("parts"))})).collect::<Vec<_>>()).unwrap_or_default();
        let canonical =
            serde_json::json!({"model":model,"messages":canonical_messages,"stream":false});
        return (
            "chat/completions".into(),
            "gemini".into(),
            serde_json::to_vec(&canonical).unwrap_or_default(),
        );
    }
    (path.into(), "openai".into(), body.to_vec())
}

fn adapt_inbound_response(
    protocol: &str,
    value: serde_json::Value,
    model: &str,
) -> serde_json::Value {
    match protocol {
        "anthropic" => {
            let text = value
                .pointer("/choices/0/message/content")
                .and_then(|item| item.as_str())
                .unwrap_or("");
            serde_json::json!({"id":value.get("id").cloned().unwrap_or_default(),"type":"message","role":"assistant","model":model,"content":[{"type":"text","text":text}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":value.pointer("/usage/prompt_tokens").cloned().unwrap_or_else(||serde_json::json!(0)),"output_tokens":value.pointer("/usage/completion_tokens").cloned().unwrap_or_else(||serde_json::json!(0))}})
        }
        "gemini" => {
            let text = value
                .pointer("/choices/0/message/content")
                .and_then(|item| item.as_str())
                .unwrap_or("");
            serde_json::json!({"candidates":[{"content":{"role":"model","parts":[{"text":text}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":value.pointer("/usage/prompt_tokens").cloned().unwrap_or_else(||serde_json::json!(0)),"candidatesTokenCount":value.pointer("/usage/completion_tokens").cloned().unwrap_or_else(||serde_json::json!(0)),"totalTokenCount":value.pointer("/usage/total_tokens").cloned().unwrap_or_else(||serde_json::json!(0))}})
        }
        _ => value,
    }
}

fn copy_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        if name != axum::http::header::AUTHORIZATION
            && name != axum::http::header::HOST
            && name != axum::http::header::CONTENT_LENGTH
            && name != axum::http::header::CONNECTION
        {
            builder = builder.header(name, value);
        }
    }
    builder
}

fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(
            serde_json::json!({"error":{"message":message,"type":"aiguard_gateway_error"}})
                .to_string(),
        ))
        .expect("valid error response")
}

fn row_to_channel(row: &rusqlite::Row<'_>) -> rusqlite::Result<Channel> {
    let models: String = row.get(5)?;
    Ok(Channel {
        id: row.get(0)?,
        name: row.get(1)?,
        base_url: row.get(2)?,
        api_key: row.get(3)?,
        protocol: row.get(4)?,
        models: serde_json::from_str(&models).unwrap_or_default(),
        priority: row.get(6)?,
        weight: row.get(7)?,
        enabled: row.get(8)?,
        available: row.get(9)?,
        consecutive_failures: row.get(10)?,
        latency_ms: row.get(11)?,
        last_test_at: row.get(12)?,
        last_error: row.get(13)?,
    })
}

fn query_channel(connection: &Connection, id: i64) -> Result<Option<Channel>, rusqlite::Error> {
    let mut statement = connection.prepare("SELECT id,name,base_url,api_key,protocol,models,priority,weight,enabled,available,consecutive_failures,latency_ms,last_test_at,last_error FROM gateway_channels WHERE id=?")?;
    match statement.query_row([id], row_to_channel) {
        Ok(channel) => Ok(Some(channel)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error),
    }
}

fn normalize_models(models: Vec<String>) -> Vec<String> {
    let mut output = models
        .into_iter()
        .flat_map(|item| {
            item.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    output.sort();
    output.dedup();
    output
}

fn normalize_protocol(protocol: &str) -> String {
    match protocol.trim().to_ascii_lowercase().as_str() {
        "anthropic" | "claude" => "anthropic".into(),
        "gemini" | "google" => "gemini".into(),
        _ => "openai".into(),
    }
}

fn supports_model(channel: &Channel, model: &str) -> bool {
    model.is_empty()
        || channel.models.is_empty()
        || channel
            .models
            .iter()
            .any(|item| item == "*" || item == model)
}

fn upstream_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if base.ends_with("/v1") {
        format!("{base}/{path}")
    } else {
        format!("{base}/v1/{path}")
    }
}

struct PreparedUpstream {
    url: String,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
    adapted: bool,
    stream_requested: bool,
}

fn prepare_upstream(channel: &Channel, path: &str, body: &[u8]) -> PreparedUpstream {
    let value = serde_json::from_slice::<serde_json::Value>(body).unwrap_or_default();
    let stream_requested = value
        .get("stream")
        .and_then(|item| item.as_bool())
        .unwrap_or(false);
    if path.split('?').next() != Some("chat/completions") {
        return PreparedUpstream {
            url: upstream_url(&channel.base_url, path),
            body: body.to_vec(),
            headers: vec![("authorization", format!("Bearer {}", channel.api_key))],
            adapted: false,
            stream_requested,
        };
    }
    match channel.protocol.as_str() {
        "anthropic" => {
            let mut messages = Vec::new();
            let mut system = Vec::new();
            for message in value
                .get("messages")
                .and_then(|item| item.as_array())
                .into_iter()
                .flatten()
            {
                let role = message
                    .get("role")
                    .and_then(|item| item.as_str())
                    .unwrap_or("user");
                let text = message_text(message.get("content"));
                if role == "system" {
                    system.push(text);
                } else {
                    messages.push(serde_json::json!({"role":if role=="assistant"{"assistant"}else{"user"},"content":text}));
                }
            }
            let request = serde_json::json!({"model":value.get("model").cloned().unwrap_or_default(),"messages":messages,"system":system.join("\n"),"max_tokens":value.get("max_tokens").or_else(||value.get("max_completion_tokens")).cloned().unwrap_or_else(||serde_json::json!(1024)),"temperature":value.get("temperature").cloned().unwrap_or_else(||serde_json::json!(1)),"stream":false});
            PreparedUpstream {
                url: anthropic_url(&channel.base_url),
                body: serde_json::to_vec(&request).unwrap_or_default(),
                headers: vec![
                    ("x-api-key", channel.api_key.clone()),
                    ("anthropic-version", "2023-06-01".into()),
                ],
                adapted: true,
                stream_requested,
            }
        }
        "gemini" => {
            let model = value
                .get("model")
                .and_then(|item| item.as_str())
                .unwrap_or("gemini-2.0-flash");
            let mut contents = Vec::new();
            let mut system = Vec::new();
            for message in value
                .get("messages")
                .and_then(|item| item.as_array())
                .into_iter()
                .flatten()
            {
                let role = message
                    .get("role")
                    .and_then(|item| item.as_str())
                    .unwrap_or("user");
                let text = message_text(message.get("content"));
                if role == "system" {
                    system.push(text)
                } else {
                    contents.push(serde_json::json!({"role":if role=="assistant"{"model"}else{"user"},"parts":[{"text":text}]}));
                }
            }
            let mut request = serde_json::json!({"contents":contents,"generationConfig":{"maxOutputTokens":value.get("max_tokens").or_else(||value.get("max_completion_tokens")).cloned().unwrap_or_else(||serde_json::json!(1024)),"temperature":value.get("temperature").cloned().unwrap_or_else(||serde_json::json!(1))}});
            if !system.is_empty() {
                request["systemInstruction"] =
                    serde_json::json!({"parts":[{"text":system.join("\n")}]});
            }
            PreparedUpstream {
                url: gemini_url(&channel.base_url, model, &channel.api_key),
                body: serde_json::to_vec(&request).unwrap_or_default(),
                headers: vec![],
                adapted: true,
                stream_requested,
            }
        }
        _ => PreparedUpstream {
            url: upstream_url(&channel.base_url, path),
            body: body.to_vec(),
            headers: vec![("authorization", format!("Bearer {}", channel.api_key))],
            adapted: false,
            stream_requested,
        },
    }
}

fn message_text(content: Option<&serde_json::Value>) -> String {
    match content {
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| part.get("text").and_then(|item| item.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn anthropic_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if base.ends_with("/v1") {
        format!("{base}/messages")
    } else {
        format!("{base}/v1/messages")
    }
}

fn gemini_url(base_url: &str, model: &str, key: &str) -> String {
    let base = base_url.trim_end_matches('/').trim_end_matches("/v1beta");
    format!("{base}/v1beta/models/{model}:generateContent?key={key}")
}

fn adapt_response(channel: &Channel, value: serde_json::Value, model: &str) -> serde_json::Value {
    match channel.protocol.as_str() {
        "anthropic" => {
            let text = value
                .get("content")
                .and_then(|item| item.as_array())
                .into_iter()
                .flatten()
                .filter_map(|part| part.get("text").and_then(|item| item.as_str()))
                .collect::<Vec<_>>()
                .join("");
            serde_json::json!({"id":value.get("id").cloned().unwrap_or_else(||serde_json::json!(format!("chatcmpl-aiguard-{}",Utc::now().timestamp_millis()))),"object":"chat.completion","created":Utc::now().timestamp(),"model":value.get("model").cloned().unwrap_or_else(||serde_json::json!(model)),"choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":value.get("stop_reason").cloned().unwrap_or_else(||serde_json::json!("stop"))}],"usage":{"prompt_tokens":value.pointer("/usage/input_tokens").cloned().unwrap_or_else(||serde_json::json!(0)),"completion_tokens":value.pointer("/usage/output_tokens").cloned().unwrap_or_else(||serde_json::json!(0)),"total_tokens":value.pointer("/usage/input_tokens").and_then(|item|item.as_u64()).unwrap_or(0)+value.pointer("/usage/output_tokens").and_then(|item|item.as_u64()).unwrap_or(0)}})
        }
        "gemini" => {
            let text = value
                .pointer("/candidates/0/content/parts")
                .and_then(|item| item.as_array())
                .into_iter()
                .flatten()
                .filter_map(|part| part.get("text").and_then(|item| item.as_str()))
                .collect::<Vec<_>>()
                .join("");
            serde_json::json!({"id":format!("chatcmpl-aiguard-{}",Utc::now().timestamp_millis()),"object":"chat.completion","created":Utc::now().timestamp(),"model":model,"choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],"usage":{"prompt_tokens":value.pointer("/usageMetadata/promptTokenCount").cloned().unwrap_or_else(||serde_json::json!(0)),"completion_tokens":value.pointer("/usageMetadata/candidatesTokenCount").cloned().unwrap_or_else(||serde_json::json!(0)),"total_tokens":value.pointer("/usageMetadata/totalTokenCount").cloned().unwrap_or_else(||serde_json::json!(0))}})
        }
        _ => value,
    }
}

fn adapted_response_body(value: &serde_json::Value, stream: bool) -> (Vec<u8>, &'static str) {
    if !stream {
        return (
            serde_json::to_vec(value).unwrap_or_default(),
            "application/json; charset=utf-8",
        );
    }
    let content = value
        .pointer("/choices/0/message/content")
        .and_then(|item| item.as_str())
        .unwrap_or("");
    let chunk = serde_json::json!({"id":value.get("id").cloned().unwrap_or_default(),"object":"chat.completion.chunk","created":value.get("created").cloned().unwrap_or_default(),"model":value.get("model").cloned().unwrap_or_default(),"choices":[{"index":0,"delta":{"role":"assistant","content":content},"finish_reason":"stop"}]});
    (
        format!("data: {}\n\ndata: [DONE]\n\n", chunk).into_bytes(),
        "text/event-stream; charset=utf-8",
    )
}

fn weighted_priority_order(channels: Vec<Channel>) -> Vec<Channel> {
    let mut groups = BTreeMap::<i64, Vec<Channel>>::new();
    for channel in channels {
        groups.entry(channel.priority).or_default().push(channel);
    }
    let mut output = Vec::new();
    for (_, mut group) in groups.into_iter().rev() {
        while !group.is_empty() {
            let total = group
                .iter()
                .map(|channel| channel.weight.max(1) as u64)
                .sum::<u64>();
            let mut sample = rand::rng().random_range(0..total);
            let index = group
                .iter()
                .position(|channel| {
                    let weight = channel.weight.max(1) as u64;
                    if sample < weight {
                        true
                    } else {
                        sample -= weight;
                        false
                    }
                })
                .unwrap_or(0);
            output.push(group.remove(index));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    fn channel(id: i64, priority: i64, weight: u32, available: bool, models: &[&str]) -> Channel {
        Channel {
            id,
            name: id.to_string(),
            base_url: "https://example.com".into(),
            api_key: "k".into(),
            protocol: "openai".into(),
            models: models.iter().map(|s| s.to_string()).collect(),
            priority,
            weight,
            enabled: true,
            available,
            consecutive_failures: 0,
            latency_ms: None,
            last_test_at: None,
            last_error: None,
        }
    }
    #[test]
    fn higher_priority_always_precedes_lower_priority() {
        for _ in 0..100 {
            let rows = weighted_priority_order(vec![
                channel(1, 10, 1, true, &["m"]),
                channel(2, 1, 1000, true, &["m"]),
            ]);
            assert_eq!(rows[0].id, 1);
        }
    }
    #[test]
    fn filters_unavailable_and_unsupported_channels() {
        let rows = vec![
            channel(1, 1, 100, false, &["m"]),
            channel(2, 1, 100, true, &["other"]),
            channel(3, 1, 100, true, &["m"]),
        ]
        .into_iter()
        .filter(|c| c.available && supports_model(c, "m"))
        .collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|c| c.id).collect::<Vec<_>>(), vec![3]);
    }
    #[test]
    fn builds_upstream_v1_url_once() {
        assert_eq!(
            upstream_url("https://api.example.com", "chat/completions"),
            "https://api.example.com/v1/chat/completions"
        );
        assert_eq!(
            upstream_url("https://api.example.com/v1/", "chat/completions"),
            "https://api.example.com/v1/chat/completions"
        );
    }

    #[test]
    fn converts_openai_chat_request_for_anthropic() {
        let mut channel = channel(1, 1, 100, true, &["claude-sonnet-4"]);
        channel.protocol = "anthropic".into();
        channel.base_url = "https://api.anthropic.com".into();
        let body=serde_json::to_vec(&serde_json::json!({"model":"claude-sonnet-4","messages":[{"role":"system","content":"系统要求"},{"role":"user","content":"你好"}],"stream":true})).unwrap();
        let prepared = prepare_upstream(&channel, "chat/completions", &body);
        let value: serde_json::Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(prepared.url, "https://api.anthropic.com/v1/messages");
        assert_eq!(value["system"], "系统要求");
        assert_eq!(value["messages"][0]["content"], "你好");
        assert_eq!(value["stream"], false);
        assert!(prepared.stream_requested);
    }

    #[test]
    fn converts_gemini_response_to_openai_shape() {
        let mut channel = channel(1, 1, 100, true, &["gemini-2.0-flash"]);
        channel.protocol = "gemini".into();
        let adapted = adapt_response(
            &channel,
            serde_json::json!({"candidates":[{"content":{"parts":[{"text":"测试成功"}]}}],"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":3,"totalTokenCount":5}}),
            "gemini-2.0-flash",
        );
        assert_eq!(
            adapted
                .pointer("/choices/0/message/content")
                .and_then(|item| item.as_str()),
            Some("测试成功")
        );
        assert_eq!(
            adapted
                .pointer("/usage/total_tokens")
                .and_then(|item| item.as_u64()),
            Some(5)
        );
    }

    #[test]
    fn accepts_anthropic_messages_as_unified_input() {
        let request = serde_json::json!({"model":"claude-sonnet-4","system":"遵守规则","messages":[{"role":"user","content":"你好"}]});
        let (path, protocol, body) =
            normalize_inbound_request("messages", &serde_json::to_vec(&request).unwrap());
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(path, "chat/completions");
        assert_eq!(protocol, "anthropic");
        assert_eq!(value["messages"][0]["role"], "system");
        assert_eq!(value["messages"][1]["content"], "你好");
    }

    #[test]
    fn converts_unified_response_back_to_anthropic() {
        let value = adapt_inbound_response(
            "anthropic",
            serde_json::json!({"id":"x","choices":[{"message":{"content":"完成"}}],"usage":{"prompt_tokens":2,"completion_tokens":3}}),
            "claude-sonnet-4",
        );
        assert_eq!(value["type"], "message");
        assert_eq!(value["content"][0]["text"], "完成");
        assert_eq!(value["usage"]["output_tokens"], 3);
    }

    #[test]
    fn saves_updates_and_deletes_channels() {
        let gateway = Gateway {
            connection: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            client: Client::new(),
        };
        gateway.connection.lock().unwrap().execute_batch("CREATE TABLE gateway_channels (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,base_url TEXT NOT NULL,api_key TEXT NOT NULL,protocol TEXT NOT NULL DEFAULT 'openai',models TEXT NOT NULL DEFAULT '[]',priority INTEGER NOT NULL DEFAULT 0,weight INTEGER NOT NULL DEFAULT 100,enabled INTEGER NOT NULL DEFAULT 1,available INTEGER NOT NULL DEFAULT 1,consecutive_failures INTEGER NOT NULL DEFAULT 0,latency_ms INTEGER,last_test_at TEXT,last_error TEXT);").unwrap();
        let saved = gateway
            .save_channel(ChannelInput {
                id: None,
                name: "主渠道".into(),
                base_url: "https://api.example.com/v1/".into(),
                api_key: "secret".into(),
                protocol: "openai".into(),
                models: vec!["gpt-test,gpt-test".into()],
                priority: 10,
                weight: 80,
                enabled: true,
            })
            .unwrap();
        assert_eq!(saved.base_url, "https://api.example.com/v1");
        assert_eq!(saved.models, vec!["gpt-test"]);
        let updated = gateway
            .save_channel(ChannelInput {
                id: Some(saved.id),
                name: "备用渠道".into(),
                base_url: saved.base_url,
                api_key: saved.api_key,
                protocol: saved.protocol,
                models: saved.models,
                priority: 5,
                weight: 20,
                enabled: false,
            })
            .unwrap();
        assert_eq!(updated.name, "备用渠道");
        assert!(!updated.enabled);
        gateway.delete_channel(saved.id).unwrap();
        assert!(gateway.list_channels().unwrap().is_empty());
    }
}
