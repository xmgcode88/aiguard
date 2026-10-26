use axum::http::HeaderMap;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use license_domain::{issue_payload, LicenseError};
use license_signing::{hash_device_key, LicenseSigner};
use license_storage::{code_hash, PublishVersionInput, Repository, StorageError};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    repo: Repository,
    signer: LicenseSigner,
    admin_username: String,
    admin_password: String,
    mfa: Option<Arc<TOTP>>,
    redis: Option<redis::Client>,
    metrics: Arc<Metrics>,
}
#[derive(Default)]
struct Metrics {
    requests_total: AtomicU64,
    responses_error: AtomicU64,
}
async fn observe(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    let response = next.run(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        state
            .metrics
            .responses_error
            .fetch_add(1, Ordering::Relaxed);
    }
    response
}
#[derive(Debug, Deserialize)]
struct ActivateRequest {
    activation_code: String,
    device_public_key: String,
    device_fingerprint: String,
    platform: String,
    client_version: String,
}
#[derive(Debug, Deserialize)]
struct RefreshRequest {
    license_id: Uuid,
    device_public_key: String,
}
#[derive(Debug, Deserialize)]
struct DeactivateRequest {
    license_id: Uuid,
    device_public_key: String,
}
#[derive(Debug, Deserialize)]
struct StatusQuery {
    license_id: Uuid,
    device_public_key: Option<String>,
}
#[derive(Debug, Deserialize)]
struct PublishVersionRequest {
    version: String,
    channel: String,
    platform: String,
    minimum_license_version: String,
    download_url: String,
    sha256: String,
}
#[derive(Debug, Serialize)]
struct SigningKeyResponse {
    key_id: String,
    public_key: String,
}
#[derive(Debug, Deserialize)]
struct UpdateQuery {
    platform: String,
    channel: String,
}
#[derive(Debug, Serialize)]
struct CertificateResponse {
    license_certificate: String,
    license_id: Uuid,
    offline_until: chrono::DateTime<Utc>,
    server_time: chrono::DateTime<Utc>,
}
#[derive(Debug, Serialize)]
struct StatusResponse {
    license_id: Uuid,
    status: String,
    expires_at: Option<chrono::DateTime<Utc>>,
    offline_until: chrono::DateTime<Utc>,
    device_count: i64,
    features: serde_json::Value,
    max_version: String,
}
#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ConfigAuditItem {
    key: &'static str,
    status: &'static str,
    message: String,
}

#[derive(Debug, Deserialize)]
struct GenerateCodesRequest {
    plan: license_domain::Plan,
    duration_days: i32,
    max_devices: i32,
    quantity: i32,
}
#[derive(Debug, Serialize)]
struct GenerateCodesResponse {
    codes: Vec<String>,
}
#[derive(Debug, Deserialize)]
struct AdminLoginRequest {
    username: String,
    password: String,
    mfa_code: Option<String>,
}
#[derive(Debug, Serialize)]
struct AdminLoginResponse {
    access_token: String,
    expires_in: u64,
    username: String,
}
#[derive(Debug, Deserialize)]
struct PageQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}
async fn admin_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AdminLoginRequest>,
) -> Result<Json<AdminLoginResponse>, ApiError> {
    rate_limit(&state, &headers, "admin-login", 10).await?;
    if req.username != state.admin_username || req.password != state.admin_password {
        return Err(ApiError::Code("ADMIN_UNAUTHORIZED"));
    }
    if let Some(mfa) = &state.mfa {
        let code = req
            .mfa_code
            .as_deref()
            .ok_or(ApiError::Code("MFA_REQUIRED"))?;
        if !mfa
            .check_current(code)
            .map_err(|_| ApiError::Code("MFA_UNAVAILABLE"))?
        {
            return Err(ApiError::Code("MFA_INVALID"));
        }
    }
    let token = Uuid::new_v4().to_string();
    let Some(client) = &state.redis else {
        return Err(ApiError::Code("REDIS_REQUIRED"));
    };
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| ApiError::Storage)?;
    let key = format!("aiguard:admin:session:{token}");
    let _: () = connection
        .set_ex(key, &state.admin_username, 8 * 60 * 60)
        .await
        .map_err(|_| ApiError::Storage)?;
    Ok(Json(AdminLoginResponse {
        access_token: token,
        expires_in: 8 * 60 * 60,
        username: state.admin_username.clone(),
    }))
}
async fn require_admin_session(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Code("ADMIN_LOGIN_REQUIRED"))?;
    let Some(client) = &state.redis else {
        return Err(ApiError::Code("REDIS_REQUIRED"));
    };
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| ApiError::Storage)?;
    let exists: bool = connection
        .exists(format!("aiguard:admin:session:{value}"))
        .await
        .map_err(|_| ApiError::Storage)?;
    if !exists {
        return Err(ApiError::Code("ADMIN_SESSION_EXPIRED"));
    }
    Ok(())
}
async fn admin_dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<license_storage::AdminDashboard>, ApiError> {
    require_admin_session(&headers, &state).await?;
    Ok(Json(state.repo.admin_dashboard().await?))
}
async fn admin_licenses(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Result<Json<Vec<license_storage::AdminLicenseSummary>>, ApiError> {
    require_admin_session(&headers, &state).await?;
    Ok(Json(
        state
            .repo
            .admin_licenses(q.limit.unwrap_or(50), q.offset.unwrap_or(0))
            .await?,
    ))
}
async fn admin_codes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Result<Json<Vec<license_storage::AdminCodeSummary>>, ApiError> {
    require_admin_session(&headers, &state).await?;
    Ok(Json(
        state
            .repo
            .admin_codes(q.limit.unwrap_or(50), q.offset.unwrap_or(0))
            .await?,
    ))
}
async fn admin_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Result<Json<Vec<license_storage::AdminDeviceSummary>>, ApiError> {
    require_admin_session(&headers, &state).await?;
    Ok(Json(
        state
            .repo
            .admin_devices(q.limit.unwrap_or(50), q.offset.unwrap_or(0))
            .await?,
    ))
}

async fn admin_config_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ConfigAuditItem>>, ApiError> {
    require_admin_session(&headers, &state).await?;
    let https = env::var("AIGUARD_PUBLIC_BASE_URL")
        .map(|value| value.starts_with("https://"))
        .unwrap_or(false);
    let items = vec![
        config_item(
            "DATABASE_URL",
            env::var("DATABASE_URL").is_ok(),
            "PostgreSQL 连接已配置",
            "缺少 PostgreSQL 连接",
        ),
        config_item(
            "LICENSE_SIGNING_SEED_BASE64",
            env::var("LICENSE_SIGNING_SEED_BASE64").is_ok(),
            "许可证签名密钥已配置",
            "缺少许可证签名密钥",
        ),
        config_item(
            "ADMIN_TOKEN",
            env::var("ADMIN_TOKEN").is_ok(),
            "管理员启动令牌已配置",
            "缺少管理员启动令牌",
        ),
        config_item(
            "REDIS_URL",
            state.redis.is_some(),
            "Redis 会话和限流已启用",
            "未配置 Redis，管理后台会话和分布式限流不可用",
        ),
        config_item(
            "ADMIN_MFA_SECRET",
            state.mfa.is_some(),
            "管理员 MFA 已启用",
            "未启用管理员 MFA",
        ),
        config_item(
            "AIGUARD_PUBLIC_BASE_URL",
            https,
            "公网 HTTPS 地址已配置",
            "生产环境必须通过 HTTPS 暴露 API",
        ),
    ];
    Ok(Json(items))
}

fn config_item(
    key: &'static str,
    ok: bool,
    ok_message: &'static str,
    bad_message: &'static str,
) -> ConfigAuditItem {
    ConfigAuditItem {
        key,
        status: if ok { "ok" } else { "warning" },
        message: if ok { ok_message } else { bad_message }.into(),
    }
}

async fn rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    bucket: &str,
    limit: i64,
) -> Result<(), ApiError> {
    let Some(client) = &state.redis else {
        return Ok(());
    };
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let key = format!("aiguard:ratelimit:{bucket}:{ip}");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| ApiError::Storage)?;
    let count: i64 = connection
        .incr(&key, 1_i64)
        .await
        .map_err(|_| ApiError::Storage)?;
    if count == 1 {
        let _: bool = connection
            .expire(&key, 60_i64)
            .await
            .map_err(|_| ApiError::Storage)?;
    }
    if count > limit {
        return Err(ApiError::Code("RATE_LIMITED"));
    }
    Ok(())
}
async fn admin_page() -> Html<&'static str> {
    Html(include_str!("../../../admin/index.html"))
}
async fn publish_version(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PublishVersionRequest>,
) -> Result<Json<Uuid>, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    if req.version.is_empty()
        || req.channel.is_empty()
        || req.platform.is_empty()
        || req.download_url.is_empty()
        || req.sha256.len() != 64
    {
        return Err(ApiError::Code("INVALID_REQUEST"));
    }
    let released_at = Utc::now();
    let unsigned = serde_json::json!({"version":req.version,"channel":req.channel,"platform":req.platform,"minimum_license_version":req.minimum_license_version,"download_url":req.download_url,"sha256":req.sha256,"released_at":released_at,"key_id":state.signer.key_id()});
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| ApiError::Code("INVALID_REQUEST"))?;
    let signature = state.signer.sign_bytes(&bytes);
    let id = state
        .repo
        .publish_version(PublishVersionInput {
            version: unsigned["version"].as_str().unwrap(),
            channel: unsigned["channel"].as_str().unwrap(),
            platform: unsigned["platform"].as_str().unwrap(),
            minimum_license_version: unsigned["minimum_license_version"].as_str().unwrap(),
            download_url: unsigned["download_url"].as_str().unwrap(),
            sha256: unsigned["sha256"].as_str().unwrap(),
            signature: &signature,
            released_at,
        })
        .await?;
    Ok(Json(id))
}
async fn signing_key(State(state): State<Arc<AppState>>) -> Json<SigningKeyResponse> {
    Json(SigningKeyResponse {
        key_id: state.signer.key_id().into(),
        public_key: state.signer.public_key_base64(),
    })
}
async fn generate_codes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GenerateCodesRequest>,
) -> Result<Json<GenerateCodesResponse>, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    if !(1..=1000).contains(&req.quantity) || req.duration_days < 0 || req.max_devices < 1 {
        return Err(ApiError::Code("INVALID_REQUEST"));
    }
    let codes = state
        .repo
        .create_codes(&req.plan, req.duration_days, req.max_devices, req.quantity)
        .await?;
    Ok(Json(GenerateCodesResponse {
        codes: codes.into_iter().map(|(_, code)| code).collect(),
    }))
}
#[derive(Debug, Deserialize)]
struct UpdateCodeRequest {
    duration_days: Option<i32>,
    max_devices: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
}
async fn admin_code_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<license_storage::AdminCodeSummary>, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    Ok(Json(state.repo.admin_code(id).await?))
}
async fn update_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCodeRequest>,
) -> Result<Json<license_storage::AdminCodeSummary>, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    Ok(Json(
        state
            .repo
            .update_code(id, req.duration_days, req.max_devices, req.expires_at)
            .await?,
    ))
}
async fn enable_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<license_storage::AdminCodeSummary>, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    Ok(Json(state.repo.set_code_status(id, "available").await?))
}
async fn disable_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<license_storage::AdminCodeSummary>, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    Ok(Json(state.repo.set_code_status(id, "disabled").await?))
}
async fn delete_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    state.repo.delete_code(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn revoke_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    state.repo.revoke_license(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn force_deactivate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((license_id, device_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    rate_limit(&state, &headers, "admin", 60).await?;
    require_admin_session(&headers, &state).await?;
    state
        .repo
        .force_deactivate_device(license_id, device_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn activate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<CertificateResponse>, ApiError> {
    rate_limit(&state, &headers, "license", 30).await?;
    let now = Utc::now();
    let (license, _device) = state
        .repo
        .activate(
            &code_hash(&req.activation_code),
            &req.device_public_key,
            &req.device_fingerprint,
            &req.platform,
            &req.client_version,
            now,
        )
        .await?;
    let payload = issue_payload(
        license.id,
        hash_device_key(&req.device_public_key),
        &license.plan,
        license
            .expires_at
            .map(|x| (x - now).num_days() as i32)
            .unwrap_or(0),
        license.max_version,
        license.features,
        now,
    );
    let cert = state
        .signer
        .sign(payload)
        .map_err(|_| ApiError::Code("INVALID_CERTIFICATE"))?;
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        serde_json::to_vec(&cert).map_err(|_| ApiError::Code("INVALID_CERTIFICATE"))?,
    );
    Ok(Json(CertificateResponse {
        license_certificate: encoded,
        license_id: license.id,
        offline_until: license.offline_until,
        server_time: now,
    }))
}
async fn refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<CertificateResponse>, ApiError> {
    rate_limit(&state, &headers, "license", 30).await?;
    let now = Utc::now();
    let (license, _) = state.repo.get_license(req.license_id).await?;
    state
        .repo
        .find_device(req.license_id, &req.device_public_key)
        .await?;
    license_domain::validate_license(license.status.clone(), license.expires_at, now)
        .map_err(ApiError::from)?;
    let payload = issue_payload(
        license.id,
        hash_device_key(&req.device_public_key),
        &license.plan,
        license
            .expires_at
            .map(|x| (x - now).num_days() as i32)
            .unwrap_or(0),
        license.max_version,
        license.features,
        now,
    );
    let cert = state
        .signer
        .sign(payload)
        .map_err(|_| ApiError::Code("INVALID_CERTIFICATE"))?;
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        serde_json::to_vec(&cert).map_err(|_| ApiError::Code("INVALID_CERTIFICATE"))?,
    );
    Ok(Json(CertificateResponse {
        license_certificate: encoded,
        license_id: license.id,
        offline_until: license.offline_until,
        server_time: now,
    }))
}
async fn deactivate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeactivateRequest>,
) -> Result<StatusCode, ApiError> {
    rate_limit(&state, &headers, "license", 30).await?;
    state
        .repo
        .find_device(req.license_id, &req.device_public_key)
        .await?;
    state
        .repo
        .deactivate(req.license_id, &req.device_public_key)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn status(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<StatusResponse>, ApiError> {
    let (license, count) = state.repo.get_license(q.license_id).await?;
    if let Some(key) = q.device_public_key {
        state.repo.find_device(q.license_id, &key).await?;
    }
    Ok(Json(StatusResponse {
        license_id: license.id,
        status: format!("{:?}", license.status).to_lowercase(),
        expires_at: license.expires_at,
        offline_until: license.offline_until,
        device_count: count,
        features: license.features,
        max_version: license.max_version,
    }))
}
#[axum::debug_handler]
async fn latest_update(
    State(state): State<Arc<AppState>>,
    Query(q): Query<UpdateQuery>,
) -> Result<Json<license_storage::VersionRecord>, ApiError> {
    Ok(Json(
        state.repo.latest_version(&q.platform, &q.channel).await?,
    ))
}
async fn ready(State(state): State<Arc<AppState>>) -> Result<&'static str, ApiError> {
    state.repo.ping().await?;
    if let Some(client) = &state.redis {
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| ApiError::Storage)?;
        let _: String = redis::cmd("PING")
            .query_async(&mut connection)
            .await
            .map_err(|_| ApiError::Storage)?;
    }
    Ok("ready")
}
async fn metrics(
    State(state): State<Arc<AppState>>,
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    let total = state.metrics.requests_total.load(Ordering::Relaxed);
    let errors = state.metrics.responses_error.load(Ordering::Relaxed);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        format!(
            "# HELP aiguard_http_requests_total Total HTTP requests
# TYPE aiguard_http_requests_total counter
aiguard_http_requests_total {total}
# HELP aiguard_http_responses_error_total HTTP responses with 4xx/5xx status
# TYPE aiguard_http_responses_error_total counter
aiguard_http_responses_error_total {errors}
"
        ),
    )
}
async fn health() -> &'static str {
    "ok"
}

#[derive(Debug)]
enum ApiError {
    Code(&'static str),
    Storage,
}
impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::Data(code) if code == "LICENSE_NOT_FOUND" => {
                Self::Code("LICENSE_NOT_FOUND")
            }
            StorageError::Data(code) if code == "CERTIFICATE_DEVICE_MISMATCH" => {
                Self::Code("CERTIFICATE_DEVICE_MISMATCH")
            }
            StorageError::Data(code) => Self::Code(Box::leak(code.into_boxed_str())),
            _ => Self::Storage,
        }
    }
}
impl From<LicenseError> for ApiError {
    fn from(e: LicenseError) -> Self {
        match e {
            LicenseError::Expired => Self::Code("LICENSE_EXPIRED"),
            LicenseError::Revoked => Self::Code("LICENSE_REVOKED"),
            _ => Self::Code("INVALID_CERTIFICATE"),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, msg) = match self {
            Self::Code(c) => (StatusCode::BAD_REQUEST, c, c.to_string()),
            Self::Storage => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SERVER_UNAVAILABLE",
                "service unavailable".into(),
            ),
        };
        (status, Json(ErrorResponse { code, message: msg })).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "license_api=info".into()))
        .init();
    let db = env::var("DATABASE_URL")?;
    let seed = env::var("LICENSE_SIGNING_SEED_BASE64")?;
    let repo = Repository::connect(&db).await?;
    let signer = LicenseSigner::from_base64(
        env::var("LICENSE_KEY_ID").unwrap_or_else(|_| "default".into()),
        &seed,
    )?;
    let admin_token = env::var("ADMIN_TOKEN").map_err(|_| "ADMIN_TOKEN is required")?;
    let admin_username = env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());
    let admin_password = env::var("ADMIN_PASSWORD").unwrap_or_else(|_| admin_token.clone());
    let mfa = env::var("ADMIN_MFA_SECRET")
        .ok()
        .map(|secret| {
            TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                Secret::Encoded(secret)
                    .to_bytes()
                    .expect("invalid ADMIN_MFA_SECRET"),
                Some("AIGuard".into()),
                "admin".into(),
            )
        })
        .transpose()?
        .map(Arc::new);
    let redis = env::var("REDIS_URL")
        .ok()
        .map(redis::Client::open)
        .transpose()?;
    let state = Arc::new(AppState {
        repo,
        signer,
        admin_username,
        admin_password,
        mfa,
        redis,
        metrics: Arc::new(Metrics::default()),
    });
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/admin", get(admin_page))
        .route("/api/v1/admin/auth/login", post(admin_login))
        .route("/api/v1/admin/dashboard", get(admin_dashboard))
        .route("/api/v1/admin/config/audit", get(admin_config_audit))
        .route("/api/v1/admin/licenses", get(admin_licenses))
        .route(
            "/api/v1/admin/license-codes",
            get(admin_codes).post(generate_codes),
        )
        .route("/api/v1/admin/devices", get(admin_devices))
        .route(
            "/api/v1/admin/license-codes/{id}",
            get(admin_code_detail)
                .patch(update_code)
                .delete(delete_code),
        )
        .route("/api/v1/admin/license-codes/{id}/enable", post(enable_code))
        .route(
            "/api/v1/admin/license-codes/{id}/disable",
            post(disable_code),
        )
        .route("/api/v1/licenses/activate", post(activate))
        .route("/api/v1/admin/licenses/{id}/revoke", post(revoke_license))
        .route(
            "/api/v1/admin/licenses/{license_id}/devices/{device_id}/deactivate",
            post(force_deactivate),
        )
        .route("/api/v1/licenses/refresh", post(refresh))
        .route("/api/v1/licenses/deactivate", post(deactivate))
        .route("/api/v1/licenses/status", get(status))
        .route("/api/v1/updates/latest", get(latest_update))
        .route("/api/v1/updates/signing-key", get(signing_key))
        .route("/api/v1/admin/updates/publish", post(publish_version))
        .layer(middleware::from_fn_with_state(state.clone(), observe))
        .with_state(state);
    let addr: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18765".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr,"license api listening");
    axum::serve(listener, app).await?;
    Ok(())
}
