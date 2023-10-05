#![allow(dead_code)]
use std::fmt::Display;

use hashbrown::HashSet;
use image::codecs::gif::GifDecoder;
use image::codecs::webp::WebPDecoder;
use image::ImageDecoder;
use kanidm_proto::internal::{ImageType, ImageValue};

use crate::be::dbvalue::DbValueImage;
use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetImage {
    set: HashSet<ImageValue>,
}

pub(crate) const MAX_IMAGE_HEIGHT: u32 = 1024;
pub(crate) const MAX_IMAGE_WIDTH: u32 = 1024;
/// 128kb should be enough for anyone... right? :D
pub(crate) const MAX_FILE_SIZE: u32 = 1024 * 128;

const WEBP_MAGIC: &[u8; 4] = b"RIFF";

pub mod jpg;
pub mod png;

pub trait ImageValueThings {
    fn validate_image(&self) -> Result<(), ImageValidationError>;
    fn validate_is_png(&self) -> Result<(), ImageValidationError>;
    fn validate_is_gif(&self) -> Result<(), ImageValidationError>;
    fn validate_is_jpg(&self) -> Result<(), ImageValidationError>;
    fn validate_is_webp(&self) -> Result<(), ImageValidationError>;
    fn validate_is_svg(&self) -> Result<(), ImageValidationError>;

    /// A sha256 of the filename/type/contents
    fn hash_imagevalue(&self) -> String;

    fn get_limits(&self) -> image::io::Limits {
        let mut limits = image::io::Limits::default();
        limits.max_image_height = Some(MAX_IMAGE_HEIGHT);
        limits.max_image_width = Some(MAX_IMAGE_WIDTH);
        limits
    }
}

#[derive(Debug)]
pub enum ImageValidationError {
    Acropalypse(String),
    ExceedsMaxWidth,
    ExceedsMaxHeight,
    ExceedsMaxDimensions,
    ExceedsMaxFileSize,
    InvalidImage(String),
    InvalidPngPrelude,
}

impl Display for ImageValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageValidationError::ExceedsMaxWidth => f.write_fmt(format_args!(
                "Exceeds the maximum width: {}",
                MAX_IMAGE_WIDTH
            )),
            ImageValidationError::ExceedsMaxHeight => f.write_fmt(format_args!(
                "Exceeds the maximum height: {}",
                MAX_IMAGE_HEIGHT
            )),
            ImageValidationError::ExceedsMaxFileSize => f.write_fmt(format_args!(
                "Exceeds maximum file size of {}",
                MAX_FILE_SIZE
            )),
            ImageValidationError::InvalidImage(message) => {
                if !message.is_empty() {
                    f.write_fmt(format_args!("Invalid Image: {}", message))
                } else {
                    f.write_str("Invalid Image")
                }
            }
            ImageValidationError::ExceedsMaxDimensions => f.write_fmt(format_args!(
                "Image exceeds max dimensions of {}x{}",
                MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT
            )),
            ImageValidationError::Acropalypse(message) => {
                if !message.is_empty() {
                    f.write_fmt(format_args!(
                        "Image has extra data, is vulnerable to Acropalypse: {}",
                        message
                    ))
                } else {
                    f.write_str("Image has extra data, is vulnerable to Acropalypse")
                }
            }
            ImageValidationError::InvalidPngPrelude => {
                f.write_str("Image has an invalid PNG prelude and is likely corrupt.")
            }
        }
    }
}

impl ImageValueThings for ImageValue {
    fn validate_image(&self) -> Result<(), ImageValidationError> {
        if self.contents.len() > MAX_FILE_SIZE as usize {
            return Err(ImageValidationError::ExceedsMaxFileSize);
        }

        match self.filetype {
            ImageType::Gif => self.validate_is_gif(),
            ImageType::Png => self.validate_is_png(),
            ImageType::Svg => self.validate_is_svg(),
            ImageType::Jpg => self.validate_is_jpg(),
            ImageType::Webp => self.validate_is_webp(),
        }
    }

    /// Validate the PNG file contents, and that it's actually a PNG
    fn validate_is_png(&self) -> Result<(), ImageValidationError> {
        // based on code here: https://blog.cloudflare.com/how-cloudflare-images-addressed-the-acropalypse-vulnerability/

        // this takes µs to run, where lodepng takes ms, so it comes first
        if png::png_has_trailer(&self.contents)? {
            return Err(ImageValidationError::Acropalypse(
                "PNG file has a trailer which likely indicates the acropalypse vulnerability!"
                    .to_string(),
            ));
        }

        png::png_lodepng_validate(&self.contents, &self.filename)
    }

    /// validate the JPG file contents, and that it's actually a JPG
    fn validate_is_jpg(&self) -> Result<(), ImageValidationError> {
        // check it starts with a valid header
        jpg::check_jpg_header(&self.contents)?;

        jpg::validate_decoding(&self.filename, &self.contents, self.get_limits())?;

        if jpg::has_trailer(&self.contents)? {
            Err(ImageValidationError::Acropalypse(
                "File has a trailer which likely indicates the acropalypse vulnerability!"
                    .to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// validate the GIF file contents, and that it's actually a GIF
    fn validate_is_gif(&self) -> Result<(), ImageValidationError> {
        let Ok(mut decoder) = GifDecoder::new(&self.contents[..]) else {
            return Err(ImageValidationError::InvalidImage(
                "Failed to parse GIF".to_string(),
            ));
        };
        let limit_result = decoder.set_limits(self.get_limits());
        if limit_result.is_err() {
            Err(ImageValidationError::ExceedsMaxDimensions)
        } else {
            Ok(())
        }
    }

    /// validate the SVG file contents, and that it's actually a SVG (ish)
    fn validate_is_svg(&self) -> Result<(), ImageValidationError> {
        // svg is a string so let's do this
        let svg_string = std::str::from_utf8(&self.contents).map_err(|e| {
            ImageValidationError::InvalidImage(format!(
                "Failed to parse SVG {} as a unicode string: {:?}",
                self.hash_imagevalue(),
                e
            ))
        })?;
        svg::read(svg_string).map_err(|e| {
            ImageValidationError::InvalidImage(format!(
                "Failed to parse {} as SVG: {:?}",
                self.hash_imagevalue(),
                e
            ))
        })?;
        Ok(())
    }

    /// validate the WebP file contents, and that it's actually a WebP file (as far as we can tell)
    fn validate_is_webp(&self) -> Result<(), ImageValidationError> {
        if !self.contents.starts_with(WEBP_MAGIC) {
            return Err(ImageValidationError::InvalidImage(
                "Failed to parse WebP file, invalid magic bytes".to_string(),
            ));
        }

        let Ok(mut decoder) = WebPDecoder::new(&self.contents[..]) else {
            return Err(ImageValidationError::InvalidImage(
                "Failed to parse WebP file".to_string(),
            ));
        };
        match decoder.set_limits(self.get_limits()) {
            Err(err) => {
                sketching::admin_warn!(
                    "Image validation failed while validating {}: {:?}",
                    self.filename,
                    err
                );
                Err(ImageValidationError::ExceedsMaxDimensions)
            }
            Ok(_) => Ok(()),
        }
    }

    /// A sha256 of the filename/type/contents, uses openssl so has to live here
    /// because proto don't need that jazz
    fn hash_imagevalue(&self) -> String {
        let filetype_repr = [self.filetype.clone() as u8];
        let mut hasher = openssl::sha::Sha256::new();
        hasher.update(self.filename.as_bytes());
        hasher.update(&filetype_repr);
        hasher.update(&self.contents);
        hex::encode(hasher.finish())
    }
}

impl ValueSetImage {
    pub fn new(image: ImageValue) -> Box<Self> {
        let mut set = HashSet::new();
        match image.validate_image() {
            Ok(_) => {
                set.insert(image);
            }
            Err(err) => {
                admin_error!(
                    "Image {} didn't pass validation, not adding to value! Error: {:?}",
                    image.filename,
                    err
                );
            }
        };
        Box::new(ValueSetImage { set })
    }

    // add the image, return a bool if there was a change
    pub fn push(&mut self, image: ImageValue) -> bool {
        match image.validate_image() {
            Ok(_) => self.set.insert(image),
            Err(err) => {
                admin_error!(
                    "Image didn't pass validation, not adding to value! Error: {}",
                    err
                );
                false
            }
        }
    }

    pub fn from_dbvs2(data: &[DbValueImage]) -> Result<ValueSet, OperationError> {
        Ok(Box::new(ValueSetImage {
            set: data
                .iter()
                .cloned()
                .map(|e| match e {
                    DbValueImage::V1 {
                        filename,
                        filetype,
                        contents,
                    } => ImageValue::new(filename, filetype, contents),
                })
                .collect(),
        }))
    }

    pub fn from_repl_v1(data: &[DbValueImage]) -> Result<ValueSet, OperationError> {
        let mut set: HashSet<ImageValue> = HashSet::new();
        for image in data {
            let image = match image.clone() {
                DbValueImage::V1 {
                    filename,
                    filetype,
                    contents,
                } => ImageValue::new(filename, filetype, contents),
            };
            match image.validate_image() {
                Ok(_) => {
                    set.insert(image.clone());
                }
                Err(err) => {
                    admin_error!(
                        "Image didn't pass validation, not adding to value! Error: {:?}",
                        err
                    );
                    return Err(OperationError::InvalidValueState);
                }
            }
        }

        Ok(Box::new(ValueSetImage { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and `ImageValue` is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetImage>>
    where
        T: IntoIterator<Item = ImageValue>,
    {
        let mut set: HashSet<ImageValue> = HashSet::new();
        for image in iter {
            match image.validate_image() {
                Ok(_) => set.insert(image),
                Err(err) => {
                    admin_error!(
                        "Image didn't pass validation, not adding to value! Error: {}",
                        err
                    );
                    return None;
                }
            };
        }
        Some(Box::new(ValueSetImage { set }))
    }
}

impl ValueSetT for ValueSetImage {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Image(image) => match self.set.contains(&image) {
                true => Ok(false),             // image exists, no change, return false
                false => Ok(self.push(image)), // this masks the operationerror
            },
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Image(pv) => {
                let imgset = self.set.clone();

                let res: Vec<bool> = imgset
                    .iter()
                    .filter(|image| &image.hash_imagevalue() == pv)
                    .map(|image| self.set.remove(image))
                    .collect();
                res.into_iter().any(|e| e)
            }
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Image(pvhash) => {
                if let Some(image) = self.set.iter().take(1).next() {
                    &image.hash_imagevalue() == pvhash
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set
            .iter()
            .map(|image| image.hash_imagevalue())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Image
    }

    fn validate(&self, schema_attr: &SchemaAttribute) -> bool {
        if !schema_attr.multivalue && self.set.len() > 1 {
            return false;
        }
        self.set.iter().all(|image| {
            image
                .validate_image()
                .map_err(|err| error!("Image {} failed validation: {}", image.filename, err))
                .is_ok()
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|image| image.hash_imagevalue()))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Image(
            self.set
                .iter()
                .cloned()
                .map(|e| crate::be::dbvalue::DbValueImage::V1 {
                    filename: e.filename,
                    filetype: e.filetype,
                    contents: e.contents,
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Image {
            set: self
                .set
                .iter()
                .cloned()
                .map(|e| DbValueImage::V1 {
                    filename: e.filename,
                    filetype: e.filetype,
                    contents: e.contents,
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.set
                .iter()
                .cloned()
                .map(|image| PartialValue::Image(image.hash_imagevalue())),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::Image))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_imageset() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_imageset() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    // this seems dumb
    fn as_imageset(&self) -> Option<&HashSet<ImageValue>> {
        Some(&self.set)
    }
}

#[test]
/// tests that we can load a bunch of test images and it'll throw errors in a way we expect
fn test_imagevalue_things() {
    ["gif", "png", "jpg", "webp"]
        .into_iter()
        .for_each(|extension| {
            // test should-be-bad images
            let filename = format!(
                "{}/src/valueset/image/test_images/oversize_dimensions.{extension}",
                env!("CARGO_MANIFEST_DIR")
            );
            trace!("testing {}", &filename);
            let image = ImageValue {
                filename: format!("oversize_dimensions.{extension}"),
                filetype: ImageType::try_from(extension).unwrap(),
                contents: std::fs::read(filename).unwrap(),
            };
            let res = image.validate_image();
            trace!("{:?}", &res);
            assert!(res.is_err());

            // test should-be-good images
            let filename = format!(
                "{}/src/valueset/image/test_images/ok.{extension}",
                env!("CARGO_MANIFEST_DIR")
            );
            trace!("testing {}", &filename);
            let image = ImageValue {
                filename: filename.clone(),
                filetype: ImageType::try_from(extension).unwrap(),
                contents: std::fs::read(filename).unwrap(),
            };
            let res = image.validate_image();
            trace!("validation result of {}: {:?}", image.filename, &res);
            assert!(res.is_ok());

            let filename = format!(
                "{}/src/valueset/image/test_images/ok.svg",
                env!("CARGO_MANIFEST_DIR")
            );
            let image = ImageValue {
                filename: filename.clone(),
                filetype: ImageType::Svg,
                contents: std::fs::read(&filename).unwrap(),
            };
            let res = image.validate_image();
            trace!("SVG Validation result of {}: {:?}", filename, &res);
            assert!(res.is_ok());
            assert_eq!(image.hash_imagevalue().is_empty(), false);
        })
}
