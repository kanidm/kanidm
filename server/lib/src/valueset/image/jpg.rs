use image::codecs::jpeg::JpegDecoder;
use image::ImageDecoder;
use sketching::*;

use super::ImageValidationError;

const JPEG_MAGIC: [u8; 2] = [0xff, 0xd8];
const EOI_MAGIC: [u8; 2] = [0xff, 0xd9];
const SOS_MARKER: [u8; 2] = [0xff, 0xda];

/// Checks to see if it has a valid JPEG magic bytes header
pub fn check_jpg_header(contents: &[u8]) -> Result<(), ImageValidationError> {
    if !contents.starts_with(&JPEG_MAGIC) {
        return Err(ImageValidationError::InvalidImage(
            "Failed to parse JPEG file, invalid magic bytes".to_string(),
        ));
    }
    Ok(())
}

// It's public so we can use it in benchmarking
/// Check to see if JPG is affected by acropalypse issues, returns `Ok(true)` if it is
/// based on <https://github.com/lordofpipes/acropadetect/blob/main/src/detect.ts>
pub fn has_trailer(contents: &Vec<u8>) -> Result<bool, ImageValidationError> {
    let buf = contents.as_slice();

    let mut pos = JPEG_MAGIC.len();

    while pos < buf.len() {
        let marker = &buf[pos..pos + 2];
        pos += 2;

        let segment_size_bytes: &[u8] = &buf[pos..pos + 2];
        let segment_size = u16::from_be_bytes(segment_size_bytes.try_into().map_err(|_| {
            ImageValidationError::InvalidImage("JPEG segment size bytes were invalid!".to_string())
        })?);
        // we do not add 2 because the size prefix includes the size of the size prefix
        pos += segment_size as usize;

        if marker == SOS_MARKER {
            break;
        }
    }

    // setting this to a big value so we can see if we don't find the EOI marker
    let mut eoi_index = buf.len() * 2;
    trace!("buffer length: {}", buf.len());

    // iterate through the file looking for the EOI_MAGIC bytes
    for i in pos..=(buf.len() - EOI_MAGIC.len()) {
        if buf[i..(i + EOI_MAGIC.len())] == EOI_MAGIC {
            eoi_index = i;
            break;
        }
    }

    if eoi_index > buf.len() {
        Err(ImageValidationError::InvalidImage(
            "End of image magic bytes not found in JPEG".to_string(),
        ))
    } else if (eoi_index + 2) < buf.len() {
        // there's still bytes in the buffer after the EOI magic bytes
        #[cfg(any(test, debug_assertions))]
        println!(
            "we're at pos: {} and buf len is {}, is not OK",
            eoi_index,
            buf.len()
        );
        Ok(true)
    } else {
        #[cfg(any(test, debug_assertions))]
        println!(
            "we're at pos: {} and buf len is {}, is OK",
            eoi_index,
            buf.len()
        );
        Ok(false)
    }
}

pub fn validate_decoding(
    filename: &str,
    contents: &[u8],
    limits: image::io::Limits,
) -> Result<(), ImageValidationError> {
    let mut decoder = match JpegDecoder::new(contents) {
        Ok(val) => val,
        Err(err) => {
            return Err(ImageValidationError::InvalidImage(format!(
                "Failed to parse {} as JPG: {:?}",
                filename, err
            )))
        }
    };

    match decoder.set_limits(limits) {
        Err(err) => {
            sketching::admin_warn!(
                "Image validation failed while validating {}: {:?}",
                filename,
                err
            );
            Err(ImageValidationError::ExceedsMaxDimensions)
        }
        Ok(_) => Ok(()),
    }
}

#[test]
fn test_jpg_has_trailer() {
    let file_contents = std::fs::read(format!(
        "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(!has_trailer(&file_contents).unwrap());

    // checking a known bad imagee
    let file_contents = std::fs::read(format!(
        "{}/src/valueset/image/test_images/windows11_3_cropped.jpg",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    // let test_bytes = vec![0xff, 0xd8, 0xff, 0xda, 0xff, 0xd9];
    assert!(has_trailer(&file_contents).unwrap());
}
