use std::sync::Arc;

use anyhow::Result;
use xelis_common::crypto::ecdlp;

use super::PrecomputedTablesShared;

// ECDLP Tables L1 size
// It is reduced to 13 for lower memory usage
pub const PRECOMPUTED_TABLES_L1: usize = 13;

// Precomputed tables is too heavy to be stored in local Storage, and generating it on the fly would be too slow
// So we will generate it on the server and store it in a file, and then we will read it from the file
pub fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction>(_: Option<String>, progress_report: P) -> Result<PrecomputedTablesShared> {
    let tables = ecdlp::ECDLPTables::generate_with_progress_report(progress_report)?;
    Ok(Arc::new(tables))
}