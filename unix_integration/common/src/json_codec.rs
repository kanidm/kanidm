use crate::constants::{CODEC_BYTESMUT_ALLOCATION_LIMIT, CODEC_MIMIMUM_BYTESMUT_ALLOCATION};
use bytes::{BufMut, BytesMut};
use serde::{de::DeserializeOwned, Serialize};
use std::io;
use std::marker::PhantomData;
use tokio_util::codec::{Decoder, Encoder};

const U32_WIDTH: usize = 4;

pub struct JsonCodec<D, E> {
    phantom_d: PhantomData<D>,
    phantom_e: PhantomData<E>,
}

impl<D, E> Default for JsonCodec<D, E> {
    fn default() -> Self {
        Self {
            phantom_d: PhantomData,
            phantom_e: PhantomData,
        }
    }
}

impl<D, E> Decoder for JsonCodec<D, E>
where
    D: DeserializeOwned,
{
    type Error = io::Error;
    type Item = D;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < U32_WIDTH {
            // Need more data, at least U32_WIDTH bytes for len
            return Ok(None);
        }

        let mut len = [0u8; U32_WIDTH];
        len.copy_from_slice(&src[0..U32_WIDTH]);

        let len = u32::from_be_bytes(len);
        let frame_len = U32_WIDTH + len as usize;

        if src.len() < frame_len {
            // Need more data, at least U32_WIDTH bytes for len, plus the frame size.
            return Ok(None);
        }

        // We have the data, lets go.
        let buffer = src.split_to(frame_len);
        // This is the frame bytes now.
        let frame = &buffer[U32_WIDTH..];

        let response = match serde_json::from_slice::<D>(frame) {
            Ok(msg) => Ok(Some(msg)),
            Err(json_err) => {
                error!(?json_err);
                Err(io::Error::other("Invalid JSON frame"))
            }
        };

        // Manage the buffer.
        if src.is_empty() && src.capacity() >= CODEC_BYTESMUT_ALLOCATION_LIMIT {
            trace!("buffer trim");
            let mut empty = BytesMut::with_capacity(CODEC_MIMIMUM_BYTESMUT_ALLOCATION);
            std::mem::swap(&mut empty, src);
        }

        response
    }
}

impl<D, E> Encoder<E> for JsonCodec<D, E>
where
    E: Serialize,
{
    type Error = io::Error;

    fn encode(&mut self, msg: E, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;

        // Encode how many bytes we wrote
        let len = data.len() as u32;

        if len == 0 {
            warn!("refusing to write empty frame.");
            return Ok(());
        }

        dst.put(len.to_be_bytes().as_slice());
        dst.put(data.as_slice());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{JsonCodec, U32_WIDTH};
    use bytes::BytesMut;
    use serde::{Deserialize, Serialize};
    use tokio_util::codec::{Decoder, Encoder};

    #[derive(Serialize, Deserialize, Debug)]
    enum Msg {
        Test,
    }

    #[test]
    fn test_json_codec() {
        let mut codec: JsonCodec<Msg, Msg> = JsonCodec::default();
        let mut buffer = BytesMut::new();

        // There should be nothing by default
        let out = codec.decode(&mut buffer);
        assert!(matches!(out, Ok(None)));

        // Write a frame
        codec
            .encode(Msg::Test, &mut buffer)
            .expect("Failed to encode");

        // Buffer should have bytes.
        assert_eq!(buffer.len(), U32_WIDTH + 6);

        // Decode
        let out = codec.decode(&mut buffer);
        assert!(matches!(out, Ok(Some(Msg::Test))));

        // Buffer should be trimmed.
        assert_eq!(buffer.len(), 0);

        // Queue up multiple messages.
        codec
            .encode(Msg::Test, &mut buffer)
            .expect("Failed to encode");
        codec
            .encode(Msg::Test, &mut buffer)
            .expect("Failed to encode");
        codec
            .encode(Msg::Test, &mut buffer)
            .expect("Failed to encode");

        assert_eq!(buffer.len(), (U32_WIDTH + 6) * 3);

        // Decode the first
        let out = codec.decode(&mut buffer);
        assert!(matches!(out, Ok(Some(Msg::Test))));

        // Do we have more data?
        assert_eq!(buffer.len(), (U32_WIDTH + 6) * 2);

        // Pull out the rest
        let out = codec.decode(&mut buffer);
        assert!(matches!(out, Ok(Some(Msg::Test))));
        let out = codec.decode(&mut buffer);
        assert!(matches!(out, Ok(Some(Msg::Test))));

        // Done!
        assert_eq!(buffer.len(), 0);
    }
}
