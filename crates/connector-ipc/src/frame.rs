use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{Envelope, IpcError, Result};

pub const PROTOCOL_VERSION: u32 = 4;
const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

pub async fn write_envelope<W>(writer: &mut W, envelope: &Envelope) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = Zeroizing::new(envelope.encode_to_vec());
    let length: u32 = encoded
        .len()
        .try_into()
        .map_err(|_| IpcError::Protocol("worker frame exceeds u32 length".into()))?;
    if length > MAX_FRAME_BYTES {
        return Err(IpcError::Protocol(format!(
            "worker frame exceeds {MAX_FRAME_BYTES} byte limit"
        )));
    }
    writer.write_u32(length).await?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_envelope<R>(reader: &mut R) -> Result<Option<Envelope>>
where
    R: AsyncRead + Unpin,
{
    let length = match reader.read_u32().await {
        Ok(length) => length,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if length > MAX_FRAME_BYTES {
        return Err(IpcError::Protocol(format!(
            "worker frame length {length} exceeds {MAX_FRAME_BYTES} byte limit"
        )));
    }
    let mut encoded = vec![0; length as usize];
    reader.read_exact(&mut encoded).await?;
    Ok(Some(Envelope::decode(encoded.as_slice())?))
}
