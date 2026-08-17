#![forbid(unsafe_code)]

use std::{env, io, path::PathBuf, process};

use clap::Parser;
use proof_mcp::{LocalBackend, serve};

#[derive(Debug, Parser)]
#[command(
    name = "proof-mcp",
    version,
    about = "Protocol-clean Proof MCP stdio server"
)]
struct Cli {
    /// Select the local Workspace root used by every tool call.
    #[arg(long, value_name = "PATH")]
    workspace: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let root = match cli.workspace {
        Some(root) => root,
        None => match env::current_dir() {
            Ok(root) => root,
            Err(error) => {
                eprintln!("proof-mcp: current directory is unavailable: {error}");
                process::exit(10);
            }
        },
    };
    let backend = match LocalBackend::new(root) {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("proof-mcp: Workspace selection failed: {error}");
            process::exit(10);
        }
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    if let Err(error) = serve(stdin.lock(), stdout.lock(), &backend) {
        eprintln!("proof-mcp: protocol I/O failed: {error}");
        process::exit(10);
    }
}
