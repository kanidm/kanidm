#![allow(dead_code)]
use std::fmt::Display;

use hashbrown::HashSet;
use image::codecs::gif::GifDecoder;
use image::codecs::jpeg::JpegDecoder;
use image::codecs::webp::WebPDecoder;
use image::ImageDecoder;
use kanidm_proto::internal::{ImageType, ImageValue};

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

pub(crate) trait ImageValueThings {
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
pub enum ImageValidationError {
    ExceedsMaxWidth,
    ExceedsMaxHeight,
    ExceedsMaxDimensions,
    ExceedsMaxFileSize,
    InvalidImage(String),
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
        }
    }
}

impl ImageValueThings for ImageValue {
    fn validate_image(&self) -> Result<(), ImageValidationError> {
        if self.contents.len() > MAX_FILE_SIZE as usize {
            // admin_debug!(
            //     "Image validation failed for {} {}",
            //     self.filename,
            //     Err(ImageValidationError::ExceedsMaxFileSize)
            // );
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

    /// validate the PNG file contents, and that it's actually a PNG
    fn validate_is_png(&self) -> Result<(), ImageValidationError> {
        match lodepng::decode32(&self.contents) {
            Ok(val) => {
                if val.width > MAX_IMAGE_WIDTH as usize || val.height > MAX_IMAGE_HEIGHT as usize {
                    admin_debug!(
                        "PNG validation failed for {} {}",
                        self.filename,
                        ImageValidationError::ExceedsMaxWidth
                    );
                    Err(ImageValidationError::ExceedsMaxWidth)
                } else if val.height > MAX_IMAGE_HEIGHT as usize {
                    admin_debug!(
                        "PNG validation failed for {} {}",
                        self.filename,
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

    /// validate the JPG file contents, and that it's actually a JPG
    fn validate_is_jpg(&self) -> Result<(), ImageValidationError> {
        let Ok(mut decoder) = JpegDecoder::new(&self.contents[..]) else {
            return Err(ImageValidationError::InvalidImage(
                "Failed to parse JPG".to_string(),
            ));
        };
        let limit_result = decoder.set_limits(self.get_limits());
        if limit_result.is_err() {
            #[cfg(any(test, debug_assertions))]
            println!("Image result: {:?}", limit_result);
            Err(ImageValidationError::ExceedsMaxDimensions)
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
            #[cfg(any(test, debug_assertions))]
            println!("Image result: {:?}", limit_result);
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
        let Ok(mut decoder) = WebPDecoder::new(&self.contents[..]) else {
            return Err(ImageValidationError::InvalidImage(
                "Failed to parse WebP file".to_string(),
            ));
        };
        let limit_result = decoder.set_limits(self.get_limits());
        if limit_result.is_err() {
            #[cfg(any(test, debug_assertions))]
            println!("Image result: {:?}", limit_result);
            Err(ImageValidationError::ExceedsMaxDimensions)
        } else {
            Ok(())
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

#[test]
/// tests that we can load a bunch of test images and it'll throw errors in a way we expect
fn test_imagevalue_things() {
    ["gif", "png", "jpg", "webp"]
        .into_iter()
        .for_each(|extension| {
            // test should-be-bad images
            let filename = format!(
                "{}/src/valueset/test_images/oversize_dimensions.{extension}",
                env!("CARGO_MANIFEST_DIR")
            );
            dbg!("testing", &filename);
            let image = ImageValue {
                filename: format!("oversize_dimensions.{extension}"),
                filetype: ImageType::from(extension),
                contents: std::fs::read(filename).unwrap(),
            };
            assert!(image.validate_image().is_err());

            // test should-be-good images
            let filename = format!(
                "{}/src/valueset/test_images/ok.{extension}",
                env!("CARGO_MANIFEST_DIR")
            );
            dbg!("testing", &filename);
            let image = ImageValue {
                filename: format!("ok.{extension}"),
                filetype: ImageType::from(extension),
                contents: std::fs::read(filename).unwrap(),
            };
            assert!(image.validate_image().is_ok());
        })
}

impl ValueSetImage {
    pub fn new(image: ImageValue) -> Box<Self> {
        // TODO: add tests for on-creation validation
        let mut set = HashSet::new();
        set.insert(image);
        Box::new(ValueSetImage { set })
    }

    // pushing
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

    pub fn from_dbvs2(data: &[ImageValue]) -> Result<ValueSet, OperationError> {
        Ok(Box::new(ValueSetImage {
            set: data.iter().cloned().collect(),
        }))
    }

    pub fn from_repl_v1(data: &[ImageValue]) -> Result<ValueSet, OperationError> {
        let mut set: HashSet<ImageValue> = HashSet::new();
        for image in data {
            if image.validate_image().is_ok() {
                set.insert(image.clone());
            } else {
                admin_error!("Image didn't pass validation, not adding to value!");
                return Err(OperationError::InvalidValueState);
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
            Value::Image(image) => match image.validate_image() {
                Ok(_) => Ok(self.set.insert(image)),
                Err(err) => {
                    admin_error!(
                        "Image didn't pass validation, not adding to value! Error: {}",
                        err
                    );
                    Err(OperationError::InvalidValueState)
                }
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
            PartialValue::Image(pvhash) => {
                if let Some(image) = self.set.iter().take(1).next() {
                    if &image.hash_imagevalue() == pvhash {
                        self.clear();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
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
            .map(|image| {
                let filetype_repr = [image.filetype.clone() as u8];
                let mut hasher = openssl::sha::Sha256::new();
                hasher.update(image.filename.as_bytes());
                hasher.update(&filetype_repr);
                hasher.update(&image.contents);
                hex::encode(hasher.finish())
            })
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
                .map_err(|err| {
                    debug!(
                        "Image {} failed validation: {}",
                        image.hash_imagevalue(),
                        err
                    )
                })
                .is_ok()
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|image| image.hash_imagevalue()))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Image(self.set.iter().map(|e| e.to_owned()).collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Image {
            set: self.set.iter().cloned().collect(),
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
