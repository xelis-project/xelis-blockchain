use std::sync::Arc;

use anyhow::Result;
use thiserror::Error;
use web_sys::{
    js_sys::Uint8Array,
    wasm_bindgen::{JsCast, JsValue},
    window,
    File,
    FileSystemDirectoryHandle,
    FileSystemFileHandle,
    FileSystemGetFileOptions,
    FileSystemWritableFileStream
};
use xelis_common::crypto::ecdlp::{self, ECDLPTables};
use wasm_bindgen_futures::JsFuture;
use log::info;

use super::PrecomputedTablesShared;

// ECDLP Tables L1 size
// It is reduced to 13 for lower memory usage
pub const PRECOMPUTED_TABLES_L1: usize = 13;

#[derive(Debug, Error)]
pub enum PrecomputedTablesError {
    #[error("window error")]
    Window,
    #[error("file system error")]
    FileSystem,
    #[error("directory error")]
    Directory,
    #[error("file error")]
    File,
    #[error("writable file error")]
    WritableFile,
    #[error("write error")]
    Write,
    #[error("write result error")]
    WriteResult,
    #[error("write close error")]
    WriteClose,
    #[error("into file error")]
    IntoFile,
    #[error("array buffer error")]
    ArrayBuffer,
}

macro_rules! js_future {
    ($e:expr, $err:ident) => {
        JsFuture::from($e).await.map(|v| v.unchecked_into())
    };
}

macro_rules! execute {
    ($e:expr, $err:ident) => {
        js_future!($e, $err).map_err(|_| PrecomputedTablesError::$err)
    };
}

// Check if the precomputed tables exists
pub async fn has_precomputed_tables(_: Option<String>) -> Result<bool> {
    let path = format!("precomputed_tables_{PRECOMPUTED_TABLES_L1}.bin");

    let window = window().ok_or(PrecomputedTablesError::Window)?;
    let navigator = window.navigator();
    let storage = navigator.storage();
    let directory: FileSystemDirectoryHandle = execute!(storage.get_directory(), Directory)?;

    // By default, it will not create a new file false
    let file_handle: Option<FileSystemFileHandle> = js_future!(directory.get_file_handle(path.as_str()), File).ok();

    if let Some(file_handle) = file_handle {
        // Verify the size of the file
        let file: File = execute!(file_handle.get_file(), IntoFile)?;
        let value: JsValue = execute!(file.array_buffer(), ArrayBuffer)?;
        let buffer = Uint8Array::new(&value).to_vec();
        Ok(buffer.len() == ECDLPTables::<PRECOMPUTED_TABLES_L1>::get_required_sizes().0)
    } else {
        Ok(false)
    }
}

// Precomputed tables is too heavy to be stored in local Storage, and generating it on the fly would be too slow
// So we will generate it on the server and store it in a file, and then we will read it from the file
pub async fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction>(_: Option<String>, progress_report: P) -> Result<PrecomputedTablesShared> {
    let path = format!("precomputed_tables_{PRECOMPUTED_TABLES_L1}.bin");

    let window = window().ok_or(PrecomputedTablesError::Window)?;
    let navigator = window.navigator();
    let storage = navigator.storage();
    let directory: FileSystemDirectoryHandle = execute!(storage.get_directory(), Directory)?;

    // By default, it will not create a new file false
    let file_handle: Option<FileSystemFileHandle> = js_future!(directory.get_file_handle(path.as_str()), File).ok();
    let tables = match file_handle {
        Some(file_handle) => {
            info!("Loading precomputed tables from {}", path);

            // Read the tables
            let file: File = execute!(file_handle.get_file(), IntoFile)?;
            info!("File size: {}", file.size());

            let value: JsValue = execute!(file.array_buffer(), ArrayBuffer)?;
            let buffer = Uint8Array::new(&value).to_vec();
            if buffer.len() != ECDLPTables::<PRECOMPUTED_TABLES_L1>::get_required_sizes().0 {
                info!("File stored has an invalid size, generating precomputed tables again...");
                let writable: FileSystemWritableFileStream = execute!(file_handle.create_writable(), WritableFile)?;
                generate_tables(path.as_str(), writable, progress_report).await?
            } else {
                info!("Loading {} bytes", buffer.len());
                let tables = ecdlp::ECDLPTables::from_bytes(&buffer);
                tables
            }

        },
        None => {
            info!("Generating precomputed tables");
            // Generate the tables
            let opts = FileSystemGetFileOptions::new();
            opts.set_create(true);

            let file_handle: FileSystemFileHandle = execute!(directory.get_file_handle_with_options(path.as_str(), &opts), File)?;
            let writable: FileSystemWritableFileStream = execute!(file_handle.create_writable(), WritableFile)?;

            generate_tables(path.as_str(), writable, progress_report).await?
        }
    };

    Ok(Arc::new(tables))
}

// Generate the tables and store them in a file
async fn generate_tables<const L1: usize, P: ecdlp::ProgressTableGenerationReportFunction>(path: &str, writable: FileSystemWritableFileStream, progress_report: P) -> Result<ECDLPTables<L1>> {
    let tables = ecdlp::ECDLPTables::generate_with_progress_report(progress_report)?;

    let slice = tables.as_slice();
    info!("Precomputed tables generated, storing {} bytes to {}", slice.len(), path);
    // We are forced to copy the slice to a buffer
    // which means we are using twice the memory
    let buffer = Uint8Array::new_with_length(slice.len() as u32);
    buffer.copy_from(slice);

    let promise = writable.write_with_buffer_source(&buffer).map_err(|_| PrecomputedTablesError::Write)?;
    let _: JsValue = execute!(promise, WriteResult)?;
    let _: JsValue = execute!(writable.close(), WriteClose)?;

    Ok(tables)
}