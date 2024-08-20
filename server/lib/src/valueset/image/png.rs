use super::{ImageValidationError, MAX_IMAGE_HEIGHT, MAX_IMAGE_WIDTH};
use crate::prelude::*;
static PNG_PRELUDE: &[u8] = &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
static PNG_CHUNK_END: &[u8; 4] = b"IEND";

#[derive(Debug)]
/// This is used as part of PNG validation to identify if we've seen the end of the file, and if it suffers from
/// Acropalypse issues by having trailing data.
enum PngChunkStatus {
    SeenEnd { has_trailer: bool },
    MoreChunks,
}

/// Loop over the PNG file contents to find out if we've got valid chunks
fn png_consume_chunks_until_iend(
    buf: &[u8],
) -> Result<(PngChunkStatus, &[u8]), ImageValidationError> {
    // length[u8;4] + chunk_type[u8;4] + checksum[u8;4] + minimum size
    if buf.len() < 12 {
        return Err(ImageValidationError::InvalidImage(format!(
            "PNG file is too short to be valid, got {} bytes",
            buf.len()
        )));
    } else {
        #[cfg(any(debug_assertions, test))]
        trace!("input buflen: {}", buf.len());
    }
    let (length_bytes, buf) = buf.split_at(4);
    let (chunk_type, buf) = buf.split_at(4);

    // Infallible: We've definitely consumed 4 bytes
    let length = u32::from_be_bytes(
        length_bytes
            .try_into()
            .map_err(|_| ImageValidationError::InvalidImage("PNG corrupt!".to_string()))?,
    );
    #[cfg(any(debug_assertions, test))]
    trace!(
        "length_bytes: {:?} length: {} chunk_type: {:?} buflen: {}",
        length_bytes,
        &length,
        &chunk_type,
        &buf.len()
    );

    if buf.len() < (length + 4) as usize {
        return Err(ImageValidationError::InvalidImage(format!(
            "PNG file is too short to be valid, failed to split at the chunk length {}, had {} bytes",
            length,
            buf.len(),
        )));
    }
    let (_, buf) = buf.split_at(length as usize);
    #[cfg(any(debug_assertions, test))]
    trace!("new buflen: {}", &buf.len());

    let (_checksum, buf) = buf.split_at(4);
    #[cfg(any(debug_assertions, test))]
    trace!("post-checksum buflen: {}", &buf.len());

    if chunk_type == PNG_CHUNK_END {
        if buf.is_empty() {
            Ok((PngChunkStatus::SeenEnd { has_trailer: false }, buf))
        } else {
            Ok((PngChunkStatus::SeenEnd { has_trailer: true }, buf))
        }
    } else {
        Ok((PngChunkStatus::MoreChunks, buf))
    }
}

// needs to be pub for bench things
pub fn png_has_trailer(contents: &Vec<u8>) -> Result<bool, ImageValidationError> {
    let buf = contents.as_slice();
    // let magic = buf.split_off(PNG_PRELUDE.len());
    let (magic, buf) = buf.split_at(PNG_PRELUDE.len());

    let buf = buf.to_owned();
    let mut buf = buf.as_slice();

    if magic != PNG_PRELUDE {
        return Err(ImageValidationError::InvalidPngPrelude);
    }

    loop {
        let (status, new_buf) = png_consume_chunks_until_iend(buf)?;
        buf = match status {
            PngChunkStatus::SeenEnd { has_trailer } => return Ok(has_trailer),
            PngChunkStatus::MoreChunks => new_buf,
        };
    }
}

// needs to be pub for bench things
pub fn png_lodepng_validate(
    contents: &Vec<u8>,
    filename: &str,
) -> Result<(), ImageValidationError> {
    match lodepng::decode32(contents) {
        Ok(val) => {
            if val.width > MAX_IMAGE_WIDTH as usize || val.height > MAX_IMAGE_HEIGHT as usize {
                admin_debug!(
                    "PNG validation failed for {} {}",
                    filename,
                    ImageValidationError::ExceedsMaxWidth
                );
                Err(ImageValidationError::ExceedsMaxWidth)
            } else if val.height > MAX_IMAGE_HEIGHT as usize {
                admin_debug!(
                    "PNG validation failed for {} {}",
                    filename,
                    ImageValidationError::ExceedsMaxHeight
                );
                Err(ImageValidationError::ExceedsMaxHeight)
            } else {
                Ok(())
            }
        }
        Err(err) => {
            // admin_debug!("PNG validation failed for {} {:?}", self.filename, err);
            Err(ImageValidationError::InvalidImage(format!("{:?}", err)))
        }
    }
}

#[test]
/// this tests a variety of input options for `png_consume_chunks_until_iend`
fn test_png_consume_chunks_until_iend() {
    let mut testchunks = vec![0, 0, 0, 1]; // the length

    testchunks.extend(PNG_CHUNK_END); // ... the type of chunk we're looking at!
    testchunks.push(1); // the data
    testchunks.extend([0, 0, 0, 1]); // the 4-byte checksum which we ignore
    let expected: [u8; 0] = [];
    let testchunks_slice = testchunks.as_slice();
    let res = png_consume_chunks_until_iend(&testchunks_slice);

    // simple, valid image works
    match res {
        Ok((result, buf)) => {
            if let PngChunkStatus::MoreChunks = result {
                panic!("Shouldn't have more chunks!");
            }
            assert_eq!(buf, &expected);
        }
        Err(err) => panic!("Error: {:?}", err),
    };

    // let's make sure it works with a bunch of different length inputs
    let mut x = 11;
    while x > 0 {
        let newslice = &testchunks_slice[0..=x];
        let res = png_consume_chunks_until_iend(newslice);
        trace!("chunkstatus at size {} {:?}", x, &res);
        assert!(res.is_err());
        x -= 1;
    }
}
