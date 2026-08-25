//! `proof-server` binary entry point (contract §"Topology and trust
//! boundaries").
//!
//! The binary resolves the deployment configuration from the environment,
//! opens and migrates the PostgreSQL authority store, binds the configured
//! listener, and serves the frozen nine-route router until SIGTERM or SIGINT
//! triggers a graceful shutdown. TLS termination is a deployment prerequisite
//! outside this adapter.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use proof_server::{AppState, ServerConfig, ServerError};
use proof_remote::oracle::IdentityFixtureV1;

/// Environment variable selecting the listen address. Defaults to the
/// loopback development address.
const LISTEN_ADDR_ENV: &str = "PROOF_LISTEN_ADDR";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";

/// Environment variable selecting the single Workspace identity. Defaults to
/// the fixed development Workspace `UUIDv7` shared with the delivery worker.
const WORKSPACE_ID_ENV: &str = "PROOF_WORKSPACE_ID";
const DEFAULT_WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000010";

/// Environment variable selecting the PostgreSQL authority store DSN.
const DSN_ENV: &str = "PROOF_PG_DSN";

/// Environment variable carrying the hex-encoded 32-byte session/CSRF hashing
/// secret. A deployment that omits it runs with a fixed development secret and
/// is not production-safe.
const SESSION_SECRET_ENV: &str = "PROOF_SESSION_SECRET";

fn main() -> ExitCode {
    // Configuration and the synchronous PostgreSQL migration path run before
    // the async runtime starts: the retained synchronous driver must never be
    // entered from inside a Tokio worker.
    let Some(config) = build_config() else {
        return ExitCode::FAILURE;
    };
    let state = AppState::new(config);
    if let Err(error) = state.connect_pg() {
        report(&error);
        return ExitCode::FAILURE;
    }
    let app = proof_server::routes::router(state.clone());
    let addr = state.config.listen_addr;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            eprintln!("proof-server: cannot start the async runtime: {error}");
            ExitCode::FAILURE
        });
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(exit) => return exit,
    };
    runtime.block_on(serve(app, addr))
}

async fn serve(app: axum::Router, addr: SocketAddr) -> ExitCode {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("proof-server: cannot bind {addr}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Ok(bound) = listener.local_addr() else {
        eprintln!("proof-server: cannot resolve the bound address");
        return ExitCode::FAILURE;
    };
    println!("proof-server listening on {bound}");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    match proof_server::serve_until(app, listener, shutdown_signal()).await {
        Ok(()) => {
            println!("proof-server shut down cleanly");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Builds the deployment configuration from the environment.
#[allow(clippy::vec_init_then_push)]
fn build_config() -> Option<ServerConfig> {
    let listen_addr: SocketAddr = std::env::var(LISTEN_ADDR_ENV)
        .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_owned())
        .parse()
        .map_err(|error| {
            eprintln!("proof-server: invalid {LISTEN_ADDR_ENV}: {error}");
            ExitCode::FAILURE
        })
        .ok()?;
    let workspace_id = std::env::var(WORKSPACE_ID_ENV)
        .unwrap_or_else(|_| DEFAULT_WORKSPACE_ID.to_owned())
        .parse()
        .map_err(|error| {
            eprintln!("proof-server: invalid {WORKSPACE_ID_ENV}: {error}");
            ExitCode::FAILURE
        })
        .ok()?;
    let dsn = std::env::var(DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned());

    let mut session_secret = [0x5a_u8; 32];
    if let Ok(encoded) = std::env::var(SESSION_SECRET_ENV) {
        let decoded = decode_secret(&encoded)?;
        session_secret = decoded;
    } else {
        eprintln!(
            "proof-server: warning: {SESSION_SECRET_ENV} is unset; \
             using the fixed development session secret"
        );
    }

    // The first-profile issuer is deterministic and in-process; its pinned
    // configuration mirrors the retained conformance vector byte-for-byte so
    // the login flow works without an external provider.
    let fixture = IdentityFixtureV1::deterministic();
    let mut config = ServerConfig::new(
        listen_addr,
        workspace_id,
        fixture.issuer_configuration,
        "deployment-secret:proof-oidc-client",
        session_secret,
        dsn,
    );
    config.deadline = Duration::from_secs(30);
    Some(config)
}

fn decode_secret(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64 {
        eprintln!(
            "proof-server: {SESSION_SECRET_ENV} must be 64 hex characters encoding 32 bytes"
        );
        return None;
    }
    let mut secret = [0_u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .inspect_err(|error| {
                eprintln!("proof-server: invalid {SESSION_SECRET_ENV} hex: {error}");
            })
            .ok()?;
    }
    Some(secret)
}

fn report(error: &ServerError) {
    eprintln!("proof-server: {error}");
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("proof-server:   caused by: {cause}");
        source = cause.source();
    }
}

/// Resolves on SIGTERM or SIGINT so container orchestrators stop the server
/// without dropping in-flight requests.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                eprintln!("proof-server: cannot install SIGTERM handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
