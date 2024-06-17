use std::{fs::{create_dir_all, File}, io::{Read, Write}, path::Path, sync::Arc};

use anyhow::Result;
use log::info;
use xelis_common::crypto::ecdlp;

use super::{PrecomputedTables, PrecomputedTablesShared};

// This will read from file if exists, or generate and store it in file
// This must be call only one time, and can be cloned to be shared through differents wallets
pub fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction>(path: Option<String>, progress_report: P, l1: usize) -> Result<PrecomputedTablesShared> {
    let mut precomputed_tables = PrecomputedTables::new(l1);

    if let Some(path) = path.as_ref() {
        let path = Path::new(&path);
        if !path.exists() {
            create_dir_all(path)?;
        }
    }
    let path = path.unwrap_or_default();

    // Try to read from file
    if let Ok(mut file) = File::open(format!("{path}precomputed_tables_{l1}.bin")) {
        info!("Reading precomputed tables from file");
        file.read_exact(precomputed_tables.get_mut())?;
    } else {
        // File does not exists, generate and store it
        info!("Generating precomputed tables");
        ecdlp::table_generation::create_table_file_with_progress_report(l1, precomputed_tables.get_mut(), progress_report)?;
        File::create(format!("{path}precomputed_tables_{l1}.bin"))?.write_all(precomputed_tables.get())?;
    }

    Ok(Arc::new(precomputed_tables))
}