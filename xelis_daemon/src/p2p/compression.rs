use chacha20poly1305::aead::Buffer;
use human_bytes::human_bytes;
use snap::raw::{Decoder, Encoder};
use thiserror::Error;
use log::trace;
use xelis_common::tokio::sync::Mutex;

use crate::config::PEER_MAX_PACKET_SIZE;

pub const COMPRESSION_THRESHOLD: usize = 1024; // 1 KiB

#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("Compression error")]
    Compression,
    #[error("Decompression error")]
    Decompression,
    #[error("Buffer error")]
    Buffer,
    #[error("Already initialized")]
    Initialized,
}

pub struct Compression {
    // Encoder & Decoder for compressing/decompressing packets
    // they both have their own buffer to avoid reallocating all the time
    encoder: Mutex<Option<(Encoder, Vec<u8>)>>,
    decoder: Mutex<Option<(Decoder, Vec<u8>)>>,
}

impl Compression {
    pub fn new() -> Self {
        Self {
            encoder: Mutex::new(None),
            decoder: Mutex::new(None),
        }
    }

    // Setup the encoder & decoder with their buffers
    pub async fn enable(&self) -> Result<(), CompressionError> {
        {
            let mut lock = self.encoder.lock().await;
            if lock.is_some() {
                return Err(CompressionError::Initialized);
            }

            let buffer = vec![0; snap::raw::max_compress_len(PEER_MAX_PACKET_SIZE as usize)];
            *lock = Some((Encoder::new(), buffer));
        }

        {
            let mut lock = self.decoder.lock().await;
            if lock.is_some() {
                return Err(CompressionError::Initialized);
            }

            let buffer = vec![0; PEER_MAX_PACKET_SIZE as usize];
            *lock = Some((Decoder::new(), buffer));
        }

        Ok(())
        
    }

    // Compress the input buffer if its size is greater than COMPRESSION_THRESHOLD
    pub async fn compress(&self, input: &mut impl Buffer) -> Result<(), CompressionError> {
        if let Some((encoder, buffer)) = self.encoder.lock().await.as_mut() {     
            let should_compress = input.len() > COMPRESSION_THRESHOLD;
            if should_compress {    
                let mut n = encoder.compress(input.as_ref(), buffer)
                .map_err(|_| CompressionError::Compression)?;
            
                trace!("Packet compressed from {} to {}", human_bytes(input.len() as f64), human_bytes(n as f64));
                if input.len() < n {
                    trace!("Packet size increased after compression: {} -> {}", input.len(), n);
                    input.extend_from_slice(&buffer[input.len()..n])
                        .map_err(|_| CompressionError::Buffer)?;
    
                    trace!("New packet size: {}", input.len());
                    n = input.len();
                } else {
                    input.truncate(n);
                }
    
                // now, re inject the compressed data in our input buffer
                input.as_mut().copy_from_slice(&buffer[..n]);
            }
    
            // if the packet was compressed, we need to add a byte at the end to indicate that
            input.extend_from_slice(&[should_compress as u8])
                .map_err(|_| CompressionError::Buffer)?;
        }

        Ok(())
    }

    // Decompress the input buffer if the last byte indicates that it was compressed
    pub async fn decompress(&self, buf: &mut impl Buffer) -> Result<(), CompressionError> {
        if let Some((decoder, buffer)) = self.decoder.lock().await.as_mut() {
            if buf.len() < 1 {
                return Err(CompressionError::Buffer);
            }
    
            // check that we have the compression flag at the end
            let compressed = buf.as_ref()[buf.len() - 1] == 1;
            buf.truncate(buf.len() - 1);
    
            if compressed {    
                let mut n = decoder.decompress(buf.as_ref(), buffer)
                    .map_err(|_| CompressionError::Decompression)?;
    
                trace!("Packet decompressed from {} to {}", buf.len(), n);
    
                // now, assemble the buffer by calculating the new length
                if n > buf.len() {
                    buf.extend_from_slice(&buffer[buf.len()..n])
                        .map_err(|_| CompressionError::Buffer)?;
    
                    n = buf.len();
                } else {
                    buf.truncate(n);
                }
    
                // reinject in our buffer the decompressed data
                buf.as_mut().copy_from_slice(&buffer[..n]);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compression() {
        let compression = Compression::new();
        compression.enable().await.unwrap();

        let data = vec![0u8; 2048];
        let mut buffer = data.clone();

        compression.compress(&mut buffer).await.unwrap();
        assert!(buffer.len() < data.len() + 1); // +1 for the compression flag

        compression.decompress(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..data.len()], &data[..]);
    }
}