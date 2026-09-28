//! Shared bounded JPEG and JPEG 2000 checks for ICAO eMRTD image fields.

use image::{codecs::jpeg::JpegDecoder, ImageDecoder};
use j2k::{DecodeSettings, J2kDecoder};

use super::{ensure_bounded, EmrtdDataError, EmrtdDataResult};

pub(crate) fn verify_icao_image(
    data: &[u8],
    expected_dimensions: Option<(u16, u16)>,
) -> EmrtdDataResult<()> {
    ensure_bounded(data, "ICAO image")?;
    if data.starts_with(&[0xff, 0xd8]) {
        verify_jpeg(data, expected_dimensions)
    } else if data.starts_with(&[0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20])
        || data.starts_with(&[0xff, 0x4f, 0xff, 0x51])
    {
        verify_jpeg2000(data, expected_dimensions)
    } else {
        Err(invalid("ICAO image is neither JPEG nor JPEG 2000"))
    }
}

fn verify_jpeg(data: &[u8], expected_dimensions: Option<(u16, u16)>) -> EmrtdDataResult<()> {
    if !data.ends_with(&[0xff, 0xd9]) {
        return Err(invalid("truncated ICAO JPEG image"));
    }
    let mut decoder = JpegDecoder::new(std::io::Cursor::new(data))
        .map_err(|_| invalid("invalid ICAO JPEG image"))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(64 * 1024 * 1024);
    decoder
        .set_limits(limits)
        .map_err(|_| invalid("ICAO JPEG image exceeds limits"))?;
    let dimensions = decoder.dimensions();
    check_dimensions(dimensions, expected_dimensions)?;
    let size = usize::try_from(decoder.total_bytes())
        .map_err(|_| invalid("ICAO JPEG image allocation overflow"))?;
    if size > 64 * 1024 * 1024 {
        return Err(invalid("ICAO JPEG image exceeds allocation limit"));
    }
    let mut pixels = vec![0u8; size];
    decoder
        .read_image(&mut pixels)
        .map_err(|_| invalid("invalid ICAO JPEG pixels"))
}

fn verify_jpeg2000(data: &[u8], expected_dimensions: Option<(u16, u16)>) -> EmrtdDataResult<()> {
    let info = J2kDecoder::inspect(data).map_err(|_| invalid("invalid ICAO JPEG 2000 header"))?;
    check_dimensions(info.dimensions, expected_dimensions)?;
    if !(1..=4).contains(&info.components) || !(1..=16).contains(&info.bit_depth) {
        return Err(invalid("unsupported ICAO JPEG 2000 component layout"));
    }
    let decoded_bytes = u64::from(info.dimensions.0)
        * u64::from(info.dimensions.1)
        * u64::from(info.components)
        * 2;
    if decoded_bytes > 64 * 1024 * 1024 {
        return Err(invalid("ICAO JPEG 2000 image exceeds allocation limit"));
    }
    let mut decoder = J2kDecoder::new_with_settings(data, DecodeSettings::strict())
        .map_err(|_| invalid("invalid ICAO JPEG 2000 image"))?;
    decoder
        .decode_components()
        .map_err(|_| invalid("invalid ICAO JPEG 2000 pixels"))?;
    Ok(())
}

fn check_dimensions(actual: (u32, u32), expected: Option<(u16, u16)>) -> EmrtdDataResult<()> {
    if actual.0 == 0 || actual.1 == 0 || actual.0 > 4096 || actual.1 > 4096 {
        return Err(invalid("ICAO image dimensions exceed limits"));
    }
    if let Some((width, height)) = expected {
        if actual != (u32::from(width), u32::from(height)) {
            return Err(invalid("ICAO image dimensions differ from record"));
        }
    }
    Ok(())
}

fn invalid(message: &str) -> EmrtdDataError {
    EmrtdDataError::InvalidFormat(message.into())
}

#[cfg(test)]
mod tests {
    use super::verify_icao_image;

    #[test]
    fn generated_jpeg2000_image_decodes_with_bounded_dimensions() {
        let image = include_bytes!("../../tests/fixtures/passport_face_2x2.jp2");
        assert!(verify_icao_image(image, Some((2, 2))).is_ok());
        assert!(verify_icao_image(image, Some((3, 2))).is_err());
        assert!(verify_icao_image(&image[..image.len() - 1], Some((2, 2))).is_err());
    }
}
