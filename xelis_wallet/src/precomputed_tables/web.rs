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
use xelis_common::crypto::ecdlp;
use wasm_bindgen_futures::JsFuture;

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

    Ok(file_handle.is_some())
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
        Some(file) => {
            // Read the tables
            let file: File = execute!(file.get_file(), IntoFile)?;
            let value: JsValue = execute!(file.array_buffer(), ArrayBuffer)?;
            let buffer = Uint8Array::new(&value).to_vec();

            let tables = ecdlp::ECDLPTables::from_bytes(&buffer);
            tables
        },
        None => {
            // Generate the tables
            let opts = FileSystemGetFileOptions::new();
            opts.set_create(true);

            let file_handle: FileSystemFileHandle = execute!(directory.get_file_handle_with_options(path.as_str(), &opts), File)?;
            let writable: FileSystemWritableFileStream = execute!(file_handle.create_writable(), WritableFile)?;

            let tables = ecdlp::ECDLPTables::generate_with_progress_report(progress_report)?;
            let promise = writable.write_with_u8_array(tables.as_slice()).map_err(|_| PrecomputedTablesError::Write)?;
            let _: JsValue = execute!(promise, WriteResult)?;

            tables
        }
    };

    Ok(Arc::new(tables))
}