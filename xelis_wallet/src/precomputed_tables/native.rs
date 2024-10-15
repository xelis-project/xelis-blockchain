use std::{
    fs::create_dir_all,
    path::Path,
    sync::Arc
};

use anyhow::Result;
use log::info;
use xelis_common::crypto::ecdlp;

use super::PrecomputedTablesShared;

// ECDLP Tables L1 size
// L1 at 26 is around ~330 MB of RAM and support up to 2^48 values
pub const PRECOMPUTED_TABLES_L1: usize = 26;

// Check if the precomputed tables exists
pub async fn has_precomputed_tables(path: Option<String>) -> Result<bool> {
    let path = path.unwrap_or_default();
    let full_path = format!("{path}precomputed_tables_{PRECOMPUTED_TABLES_L1}.bin");

    Ok(Path::new(&full_path).exists())
}

// This will read from file if exists, or generate and store it in file
// This must be call only one time, and can be cloned to be shared through differents wallets
pub async fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction>(mut path: Option<String>, progress_report: P) -> Result<PrecomputedTablesShared> {
    if let Some(path) = path.as_mut() {
        if !path.ends_with('/') {
            path.push_str("/");
        }

        let path = Path::new(&path);
        if !path.exists() {
            create_dir_all(path)?;
        }
    }

    let path = path.unwrap_or_default();
    let full_path = format!("{path}precomputed_tables_{PRECOMPUTED_TABLES_L1}.bin");

    let tables = if Path::new(&full_path).exists() {
        info!("Loading precomputed tables from {}", full_path);
        ecdlp::ECDLPTables::load_from_file(PRECOMPUTED_TABLES_L1, full_path.as_str())?
    } else {
        // File does not exists, generate and store it
        info!("Generating precomputed tables");
        let tables = ecdlp::ECDLPTables::generate_with_progress_report(PRECOMPUTED_TABLES_L1, progress_report)?;
        info!("Precomputed tables generated, storing to {}", full_path);
        tables.write_to_file(full_path.as_str())?;

        tables
    };

    Ok(Arc::new(tables))
}