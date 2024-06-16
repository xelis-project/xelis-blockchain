use std::sync::Arc;

use anyhow::Result;
use xelis_common::crypto::ecdlp;

use super::{PrecomputedTables, PrecomputedTablesShared};

// Precomputed tables is too heavy to be stored in local Storage, and generating it on the fly would be too slow
// So we will generate it on the server and store it in a file, and then we will read it from the file
pub fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction>(_: Option<String>, _: P, l1: usize) -> Result<PrecomputedTablesShared> {
    let mut precomputed_tables = PrecomputedTables::new(l1);
    let bytes = include_bytes!("precomputed_tables.bin");
    precomputed_tables.get_mut().copy_from_slice(bytes);
    Ok(Arc::new(precomputed_tables))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdlp::NoOpProgressTableGenerationReportFunction;
    use xelis_common::crypto::ecdlp::table_generation::table_file_len;

    #[test]
    fn test_read_or_generate_precomputed_tables() {
        let l1 = 26;
        let precomputed_tables = read_or_generate_precomputed_tables(None, NoOpProgressTableGenerationReportFunction, l1).unwrap();
        let expected = table_file_len(l1);
        assert_eq!(precomputed_tables.bytes_count, expected);
        assert_eq!(precomputed_tables.get().len(), expected);

        let bytes = include_bytes!("precomputed_tables.bin");
        assert_eq!(precomputed_tables.get(), bytes);
        assert_eq!(bytes.len(), expected);
    }
}