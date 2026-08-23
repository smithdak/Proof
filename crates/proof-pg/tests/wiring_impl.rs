//! Integration tests for the wired `PostgreSQL` runtime: connect, durability
//! preconditions, schema bootstrap migration, and the Workspace write lane.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use proof_domain::WorkspaceId;
use proof_pg::{PgConfig, wiring::PgRuntime};

const WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000010";

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

/// A runtime connected to a dedicated isolated schema, dropped on teardown.
struct IsolatedRuntime {
    runtime: PgRuntime,
    schema: String,
}

impl IsolatedRuntime {
    fn new() -> Self {
        let workspace_id: WorkspaceId = WORKSPACE_ID.parse().expect("valid WorkspaceId");
        let mut runtime =
            PgRuntime::connect(PgConfig::new(dsn(), workspace_id, Duration::from_secs(30)))
                .expect("connect to PostgreSQL; run scripts/dev-pg.sh");
        let schema = format!(
            "p0010_wiring_{}_{}",
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        runtime
            .client_mut()
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .unwrap();
        runtime
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .unwrap();
        Self { runtime, schema }
    }

    fn table_count(&mut self) -> i64 {
        self.runtime
            .client_mut()
            .query_one(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1",
                &[&self.schema],
            )
            .unwrap()
            .get(0)
    }
}

impl Drop for IsolatedRuntime {
    fn drop(&mut self) {
        let _ = self
            .runtime
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

#[test]
fn runtime_connects_verifies_preconditions_migrates_and_begins_transaction() {
    let mut ctx = IsolatedRuntime::new();

    // The dev instance satisfies the three durability preconditions.
    ctx.runtime.verify_durability_preconditions().unwrap();

    // The first migrate bootstraps the full 14-table logged schema.
    ctx.runtime.migrate().unwrap();
    assert_eq!(ctx.table_count(), 14);

    // A second migrate is an idempotent no-op: `migration_head` now exists.
    ctx.runtime.migrate().unwrap();
    assert_eq!(ctx.table_count(), 14);

    // The bootstrap creates the tables but inserts no migration-head singleton
    // (that row is written by the migration ledger, not by `migrate`).
    let heads: i64 = ctx
        .runtime
        .client_mut()
        .query_one("SELECT COUNT(*) FROM migration_head", &[])
        .unwrap()
        .get(0);
    assert_eq!(heads, 0);

    // The write lane opens a serializable transaction that commits cleanly.
    let transaction = ctx.runtime.begin_workspace_transaction().unwrap();
    transaction.commit().unwrap();
}
