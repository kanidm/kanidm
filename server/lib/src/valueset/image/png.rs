use super::{ImageValidationError, MAX_IMAGE_HEIGHT, MAX_IMAGE_WIDTH};
use crate::prelude::*;
static PNG_PRELUDE: &[u8] = &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
static PNG_CHUNK_IHDR: &[u8; 4] = b"IHDR";
static PNG_CHUNK_END: &[u8; 4] = b"IEND";

#[derive(Debug)]
/// This is used as part of PNG validation to identify if we've seen the end of the file, and if it suffers from
/// Acropalypse issues by having trailing data.
enum PngChunkStatus {
    SeenEnd { has_trailer: bool },
    MoreChunks,
}

fn png_split_chunk(buf: &[u8]) -> Result<(&[u8], &[u8], &[u8]), ImageValidationError> {
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

    if buf.len() < (length as usize).saturating_add(4) {
        return Err(ImageValidationError::InvalidImage(format!(
            "PNG file is too short to be valid, failed to split at the chunk length {}, had {} bytes",
            length,
            buf.len(),
        )));
    }
    let (chunk_data, buf) = buf.split_at(length as usize);
    #[cfg(any(debug_assertions, test))]
    trace!("new buflen: {}", &buf.len());

    let (_checksum, buf) = buf.split_at(4);
    #[cfg(any(debug_assertions, test))]
    trace!("post-checksum buflen: {}", &buf.len());

    Ok((chunk_type, chunk_data, buf))
}

fn png_validate_ihdr(chunk_type: &[u8], chunk_data: &[u8]) -> Result<(), ImageValidationError> {
    if chunk_type != PNG_CHUNK_IHDR {
        return Err(ImageValidationError::InvalidImage(
            "PNG first chunk must be IHDR".to_string(),
        ));
    }

    if chunk_data.len() != 13 {
        return Err(ImageValidationError::InvalidImage(format!(
            "PNG IHDR chunk must be 13 bytes, got {} bytes",
            chunk_data.len()
        )));
    }

    let (width_chunk, chunk_data) = chunk_data.split_at(4);
    let (height_chunk, _rest) = chunk_data.split_at(4);
    let width = u32::from_be_bytes(
        width_chunk
            .try_into()
            .map_err(|_| ImageValidationError::InvalidImage("PNG corrupt!".to_string()))?,
    );
    let height = u32::from_be_bytes(
        height_chunk
            .try_into()
            .map_err(|_| ImageValidationError::InvalidImage("PNG corrupt!".to_string()))?,
    );

    if width == 0 || height == 0 {
        return Err(ImageValidationError::InvalidImage(
            "PNG IHDR dimensions must be non-zero".to_string(),
        ));
    }

    if width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT {
        return Err(ImageValidationError::ExceedsMaxDimensions);
    }

    Ok(())
}

/// Loop over the PNG file contents to find out if we've got valid chunks
fn png_consume_chunks_until_iend(
    buf: &[u8],
) -> Result<(PngChunkStatus, &[u8]), ImageValidationError> {
    let (chunk_type, chunk_data, buf) = png_split_chunk(buf)?;

    if chunk_type == PNG_CHUNK_END {
        if !chunk_data.is_empty() {
            return Err(ImageValidationError::InvalidImage(
                "PNG IEND chunk must be empty".to_string(),
            ));
        }

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
    if contents.len() < PNG_PRELUDE.len() {
        return Err(ImageValidationError::InvalidImage(format!(
            "PNG file is too short to be valid, got {} bytes",
            contents.len()
        )));
    }

    let (magic, mut buf) = contents.as_slice().split_at(PNG_PRELUDE.len());
    if magic != PNG_PRELUDE {
        return Err(ImageValidationError::InvalidPngPrelude);
    }

    let (chunk_type, chunk_data, new_buf) = png_split_chunk(buf)?;
    png_validate_ihdr(chunk_type, chunk_data)?;
    buf = new_buf;

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
            if val.width > MAX_IMAGE_WIDTH as usize {
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
            Err(ImageValidationError::InvalidImage(format!("{err:?}")))
        }
    }
}

#[test]
/// this tests a variety of input options for `png_consume_chunks_until_iend`
fn test_png_consume_chunks_until_iend() {
    let mut testchunks = vec![0, 0, 0, 0]; // the length

    testchunks.extend(PNG_CHUNK_END); // ... the type of chunk we're looking at!
    testchunks.extend([0, 0, 0, 1]); // the 4-byte checksum which we ignore
    let expected: [u8; 0] = [];
    let testchunks_slice = testchunks.as_slice();
    let res = png_consume_chunks_until_iend(testchunks_slice);

    // simple, valid image works
    match res {
        Ok((result, buf)) => {
            if let PngChunkStatus::MoreChunks = result {
                panic!("Shouldn't have more chunks!");
            }
            assert_eq!(buf, &expected);
        }
        Err(err) => panic!("Error: {err:?}"),
    };

    // let's make sure it works with a bunch of different length inputs
    let mut x = 10;
    while x > 0 {
        let newslice = &testchunks_slice[0..=x];
        let res = png_consume_chunks_until_iend(newslice);
        trace!("chunkstatus at size {} {:?}", x, &res);
        assert!(res.is_err());
        x -= 1;
    }
}

#[test]
fn test_png_too_short() {
    let too_short = vec![0, 0, 0, 1, 2, 3];
    let res = png_consume_chunks_until_iend(too_short.as_slice());
    assert!(res.is_err());
}

#[test]
fn audit_png_short_input_err() {
    let short = vec![0x89u8, 0x50, 0x4e, 0x47];
    assert!(png_has_trailer(&short).is_err());
}

#[test]
fn audit_png_chunk_length_overflow_errs() {
    let mut data = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFD]);
    data.extend_from_slice(PNG_CHUNK_IHDR);
    data.extend_from_slice(&[0u8; 8]);
    assert!(png_has_trailer(&data).is_err());
}

#[cfg(test)]
fn png_test_chunk(chunk_type: [u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(&chunk_type);
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(&[0u8; 4]);
    chunk
}

#[cfg(test)]
fn png_test_image_with_ihdr(width: u32, height: u32) -> Vec<u8> {
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);

    let mut data = PNG_PRELUDE.to_vec();
    data.extend_from_slice(&png_test_chunk(*PNG_CHUNK_IHDR, &ihdr));
    data.extend_from_slice(&png_test_chunk(*PNG_CHUNK_END, &[]));
    data
}

#[test]
fn audit_png_signature_without_chunks_errs() {
    let data = PNG_PRELUDE.to_vec();
    assert!(png_has_trailer(&data).is_err());
}

#[test]
fn audit_png_valid_file_with_trailing_bytes_has_trailer() {
    let mut data = include_bytes!("test_images/ok.png").to_vec();
    data.push(0);
    assert!(png_has_trailer(&data).expect("valid PNG with trailer should parse"));
}

#[test]
fn audit_png_nonzero_length_iend_errs() {
    let mut data = png_test_image_with_ihdr(1, 1);
    data.truncate(data.len() - 12);
    data.extend_from_slice(&png_test_chunk(*PNG_CHUNK_END, &[1]));
    assert!(png_has_trailer(&data).is_err());
}

#[test]
fn audit_png_first_chunk_must_be_ihdr() {
    let mut data = PNG_PRELUDE.to_vec();
    data.extend_from_slice(&png_test_chunk(*b"tEXt", &[]));
    data.extend_from_slice(&png_test_chunk(*PNG_CHUNK_END, &[]));
    assert!(png_has_trailer(&data).is_err());
}

#[test]
fn audit_png_ihdr_length_must_be_13() {
    let mut data = PNG_PRELUDE.to_vec();
    data.extend_from_slice(&png_test_chunk(*PNG_CHUNK_IHDR, &[]));
    data.extend_from_slice(&png_test_chunk(*PNG_CHUNK_END, &[]));
    assert!(png_has_trailer(&data).is_err());
}

#[test]
fn audit_png_ihdr_zero_width_or_height_errs() {
    let zero_width = png_test_image_with_ihdr(0, 1);
    let zero_height = png_test_image_with_ihdr(1, 0);
    assert!(png_has_trailer(&zero_width).is_err());
    assert!(png_has_trailer(&zero_height).is_err());
}

#[test]
fn audit_png_ihdr_over_limit_dimensions_err() {
    let too_wide = png_test_image_with_ihdr(MAX_IMAGE_WIDTH + 1, 1);
    let too_tall = png_test_image_with_ihdr(1, MAX_IMAGE_HEIGHT + 1);
    assert!(png_has_trailer(&too_wide).is_err());
    assert!(png_has_trailer(&too_tall).is_err());
}
