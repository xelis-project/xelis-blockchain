use std::sync::Arc;

use anyhow::Result;
use thiserror::Error;
use web_sys::{
    js_sys::{Reflect, Uint8Array},
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
use log::{info, warn};

use super::*;

#[derive(Debug, Error)]
pub enum PrecomputedTablesError {
    #[error("window error: {0}")]
    Window(String),
    #[error("file system error: {0}")]
    FileSystem(String),
    #[error("directory error: {0}")]
    Directory(String),
    #[error("file error: {0}")]
    File(String),
    #[error("writable file error: {0}")]
    WritableFile(String),
    #[error("write error: {0}")]
    Write(String),
    #[error("write result error: {0}")]
    WriteResult(String),
    #[error("write close error: {0}")]
    WriteClose(String),
    #[error("into file error: {0}")]
    IntoFile(String),
    #[error("array buffer error: {0}")]
    ArrayBuffer(String),
    #[error("reflect error: {0}")]
    Reflect(String),
}

macro_rules! js_future {
    ($e:expr) => {
        JsFuture::from($e).await
    };
}

macro_rules! execute {
    ($e:expr, $err:ident) => {
        js_future!($e).map(|v| v.unchecked_into()).map_err(|e| PrecomputedTablesError::$err(format!("{:?}", e)))
    };
}

// Check if the precomputed tables exists
pub async fn has_precomputed_tables(_: Option<&str>, l1: usize) -> Result<bool> {
    let path = format!("precomputed_tables_{l1}.bin");

    let window = window().ok_or(PrecomputedTablesError::Window("window not found in context".to_owned()))?;
    let navigator = window.navigator();
    let storage = navigator.storage();
    // On Safari, if directory is not available, it means he is in an ephemeral context (private tab), which is not supported by WebKit
    let directory: FileSystemDirectoryHandle = match execute!(storage.get_directory(), Directory) {
        Ok(directory) => directory,
        Err(e) => {
            warn!("Directory not available, precomputed tables cannot be present: {}", e);
            return Ok(false)
        }
    };

    // By default, it will not create a new file false
    // we check if the file exists
    // and expect the file to have the same size as the precomputed tables
    let file_handle: Option<FileSystemFileHandle> = js_future!(directory.get_file_handle(path.as_str()))
        .ok()
        .map(|v| v.unchecked_into());

    if let Some(file_handle) = file_handle {
        // Verify the size of the file
        let file: File = execute!(file_handle.get_file(), IntoFile)?;
        Ok(file.size() as usize == ECDLPTables::get_required_sizes(l1).0)
    } else {
        Ok(false)
    }
}

// Precomputed tables is too heavy to be stored in local Storage, and generating it on the fly would be too slow
// So we will generate it on the server and store it in a file, and then we will read it from the file
pub async fn read_or_generate_precomputed_tables<P: ecdlp::ProgressTableGenerationReportFunction>(_: Option<&str>, l1: usize, progress_report: P) -> Result<PrecomputedTablesShared> {
    let path = format!("precomputed_tables_{l1}.bin");

    let window = window().ok_or(PrecomputedTablesError::Window("window not found in context".to_owned()))?;
    let navigator = window.navigator();
    let storage = navigator.storage();
    let directory: Result<FileSystemDirectoryHandle, PrecomputedTablesError> = execute!(storage.get_directory(), Directory);

    // By default, it will not create a new file false
    let (file_handle, directory): (Option<FileSystemFileHandle>, Option<FileSystemDirectoryHandle>) = match directory {
        Ok(directory) => (
            js_future!(directory.get_file_handle(path.as_str()))
            .ok()
            .map(|v| v.try_into().ok())
            .flatten(),
            Some(directory)
        ),
        Err(e) => {
            warn!("Directory not available: {}", e);
            (None, None)
        }
    };

    let tables = match file_handle {
        Some(file_handle) => {
            info!("Loading precomputed tables from {}", path);

            // Read the tables
            let file: File = execute!(file_handle.get_file(), IntoFile)?;
            info!("File size: {}", file.size());

            let value: JsValue = execute!(file.array_buffer(), ArrayBuffer)?;
            let buffer = Uint8Array::new(&value).to_vec();
            if buffer.len() != ECDLPTables::get_required_sizes(l1).0 {
                info!("File stored has an invalid size, generating precomputed tables again...");
                generate_tables(path.as_str(), l1, Some(file_handle), progress_report).await?
            } else {
                info!("Loading {} bytes", buffer.len());
                let tables = ecdlp::ECDLPTables::from_bytes(l1, &buffer);
                tables
            }

        },
        None => {
            info!("Generating precomputed tables");
            // Generate the tables
            let opts = FileSystemGetFileOptions::new();
            opts.set_create(true);

            let file_handle: Option<FileSystemFileHandle> = match directory {
                Some(directory) => Some(execute!(directory.get_file_handle_with_options(path.as_str(), &opts), File)?),
                None => None
            };
            generate_tables(path.as_str(), l1, file_handle, progress_report).await?
        }
    };

    Ok(Arc::new(RwLock::new(tables)))
}

// Generate the tables and store them in a file if API is available
async fn generate_tables<P: ecdlp::ProgressTableGenerationReportFunction>(path: &str, l1: usize, file_handle: Option<FileSystemFileHandle>, progress_report: P) -> Result<ECDLPTables> {
    let tables = ecdlp::ECDLPTables::generate_with_progress_report(l1, progress_report)?;

    let slice = tables.as_slice();
    info!("Precomputed tables generated");

    let res: Option<FileSystemWritableFileStream> = match file_handle {
        Some(file_handle) => if Reflect::has(&file_handle, &JsValue::from_str("createWritable")).map_err(|e| PrecomputedTablesError::Reflect(format!("{:?}", e)))? {
            Some(execute!(file_handle.create_writable(), WritableFile)?)
        } else {
            None
        },
        None => None
    };

    if let Some(writable) = res {
        info!("Writing precomputed tables to {} with {} bytes", path, slice.len());
        // We are forced to copy the slice to a buffer
        // which means we are using twice the memory
        let buffer = Uint8Array::new_with_length(slice.len() as u32);
        buffer.copy_from(slice);

        let promise = writable.write_with_buffer_source(&buffer).map_err(|e| PrecomputedTablesError::Write(format!("{:?}", e)))?;
        let _: JsValue = execute!(promise, WriteResult)?;
        let _: JsValue = execute!(writable.close(), WriteClose)?;
    } else {
        warn!("Failed to create writable file stream, precomputed tables will not be stored");
    }

    Ok(tables)
}