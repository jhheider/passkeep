//! A thin axum wiring of passkeep: the full passkey round trip (register and
//! login) over four endpoints, with in-memory stores. It shows where passkeep
//! plugs in and how the pieces move; it is not a complete demo (there is no
//! bundled browser JavaScript to drive it). Swap the in-memory maps for your
//! session store and database.
//!
//! Run: `cargo run --example axum_rp` (listens on http://127.0.0.1:3000).
//!
//! The browser posts the WebAuthn response fields as base64url JSON; each
//! handler decodes them and hands the raw bytes to passkeep. Note how the
//! challenge is removed from the store the moment it is used, so a captured
//! response cannot be replayed (the single-use rule passkeep leaves to you).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use passkeep::{
    AssertionVerification, Challenge, CoseEs256Key, RegistrationVerification, RelyingParty,
};
use serde::Deserialize;
use serde_json::{json, Value};

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:3000";

#[derive(Default)]
struct Store {
    /// session id -> the raw challenge issued for the pending ceremony
    challenges: HashMap<String, Vec<u8>>,
    /// credential id -> the stored credential
    credentials: HashMap<Vec<u8>, StoredCredential>,
}

struct StoredCredential {
    public_key: CoseEs256Key,
    sign_count: u32,
}

type AppState = Arc<Mutex<Store>>;

type ApiError = (StatusCode, String);

fn decode(s: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad base64url: {e}")))
}

fn rp() -> RelyingParty {
    RelyingParty::new(RP_ID, ORIGIN)
}

/// Issue a challenge for either ceremony. A real app keys the pending challenge
/// by the authenticated session; here the challenge doubles as an opaque handle.
async fn start(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let challenge =
        Challenge::generate().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let session = challenge.to_base64url();
    let challenge_b64 = challenge.to_base64url();
    state
        .lock()
        .unwrap()
        .challenges
        .insert(session.clone(), challenge.into_bytes());
    Ok(Json(json!({
        "session": session,
        "rpId": RP_ID,
        "challenge": challenge_b64,
    })))
}

#[derive(Deserialize)]
struct RegisterFinish {
    session: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegisterFinish>,
) -> Result<Json<Value>, ApiError> {
    // Take the challenge out of the store: single-use, so it cannot be replayed.
    let challenge = state
        .lock()
        .unwrap()
        .challenges
        .remove(&req.session)
        .ok_or((StatusCode::BAD_REQUEST, "unknown or expired session".into()))?;

    let credential = rp()
        .verify_registration(&RegistrationVerification {
            client_data_json: &decode(&req.client_data_json)?,
            attestation_object: &decode(&req.attestation_object)?,
            expected_challenge: &challenge,
            require_user_verification: true,
        })
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&credential.credential_id);
    // A real app also rejects a credential id it already stores, and binds this
    // credential to the account that registered it.
    state.lock().unwrap().credentials.insert(
        credential.credential_id,
        StoredCredential {
            public_key: credential.public_key,
            sign_count: credential.sign_count,
        },
    );
    Ok(Json(json!({ "credentialId": credential_id_b64 })))
}

#[derive(Deserialize)]
struct LoginFinish {
    session: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
}

async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinish>,
) -> Result<Json<Value>, ApiError> {
    let challenge = state
        .lock()
        .unwrap()
        .challenges
        .remove(&req.session)
        .ok_or((StatusCode::BAD_REQUEST, "unknown or expired session".into()))?;

    let credential_id = decode(&req.credential_id)?;
    // Look the credential up by id. A real app also confirms this credential
    // belongs to the user it is trying to authenticate.
    let (public_key, previous_sign_count) = {
        let store = state.lock().unwrap();
        let cred = store
            .credentials
            .get(&credential_id)
            .ok_or((StatusCode::BAD_REQUEST, "unknown credential".into()))?;
        (cred.public_key.clone(), cred.sign_count)
    };

    let outcome = rp()
        .verify_assertion(&AssertionVerification {
            client_data_json: &decode(&req.client_data_json)?,
            authenticator_data: &decode(&req.authenticator_data)?,
            signature: &decode(&req.signature)?,
            expected_challenge: &challenge,
            credential_public_key: &public_key,
            previous_sign_count,
            require_user_verification: true,
        })
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    // Persist the advanced counter (the point of the monotonicity check).
    if let Some(cred) = state.lock().unwrap().credentials.get_mut(&credential_id) {
        cred.sign_count = outcome.new_sign_count;
    }
    Ok(Json(json!({
        "authenticated": true,
        "newSignCount": outcome.new_sign_count,
    })))
}

#[tokio::main]
async fn main() {
    let state: AppState = Arc::new(Mutex::new(Store::default()));
    let app = Router::new()
        .route("/register/start", get(start))
        .route("/register/finish", post(register_finish))
        .route("/login/start", get(start))
        .route("/login/finish", post(login_finish))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("passkeep axum example on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
