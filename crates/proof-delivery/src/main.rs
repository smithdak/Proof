//! `proof-worker` binary entry point (contract §"Transactional outbox and
//! delivery").
//!
//! This is a wiring stub: it resolves the worker configuration and hands off to
//! [`proof_delivery::worker::OutboxWorker::run_loop`] for the implementation
//! successors.

use proof_delivery::worker::{OutboxWorker, WorkerConfig};

fn main() {
    let config = WorkerConfig::from_env();
    let _ = OutboxWorker::new(config);
    todo!("connect the PostgreSQL runtime and run the outbox worker loop")
}
