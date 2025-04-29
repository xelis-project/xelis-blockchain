use std::{
    fs::create_dir_all,
    path::Path,
    sync::Arc,
    time::Instant
};

use anyhow::{bail, Result};
use log::info;
use xelis_common::{
    crypto::ecdlp,
    utils::detect_available_parallelism
};

use super::*;

// Check if the precomputed tables exists
pub async fn has_precomputed_tables(path: Option<&str>, l1: usize) -> Result<bool> {
    let path = path.unwrap_or_default();
    let full_path = format!("{path}precomputed_tables_{l1}.bin");

    Ok(Path::new(&full_path).exists())
}

// This will read from file if exists, or generate and store it in file
// This must be call only one time, and can be cloned to be shared through differents wallets
pub async fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction + Send + Sync>(path: Option<&str>, l1: usize, progress_report: P, store_on_disk: bool) -> Result<PrecomputedTablesShared> {
    if let Some(p) = &path {
        if !(p.ends_with('/') || p.ends_with('\\')) {
            bail!("Path for precomputed tables must ends with / or \\");
        }

        let path = Path::new(&p);
        if !path.exists() {
            create_dir_all(path)?;
        }
    }

    let path = path.unwrap_or_default();
    let full_path = format!("{path}precomputed_tables_{l1}.bin");

    let tables = if Path::new(&full_path).exists() {
        info!("Loading precomputed tables from {}", full_path);
        ecdlp::ECDLPTables::load_from_file(l1, full_path.as_str())?
    } else {
        // File does not exists, generate and store it
        info!("Generating precomputed tables");
        let instant = Instant::now();
        let tables = ecdlp::ECDLPTables::generate_with_progress_report_par(l1, detect_available_parallelism(), progress_report)?;
        if store_on_disk {
            info!("Precomputed tables generated, storing to {}", full_path);
            tables.write_to_file(full_path.as_str())?;
        }
        info!("Took {:?} to generate the precomputed tables", instant.elapsed());

        tables
    };

    Ok(Arc::new(RwLock::new(tables)))
}