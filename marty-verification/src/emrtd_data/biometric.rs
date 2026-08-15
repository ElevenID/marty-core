use serde::{Deserialize, Serialize};

use super::{ensure_bounded, EmrtdDataError, EmrtdDataResult};

const COMMON_HEADER_BYTES: usize = 14;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BiometricType {
    FacialImage,
    Fingerprint,
    Iris,
    Voice,
    Dna,
}

impl BiometricType {
    pub fn code(self) -> u8 {
        match self {
            Self::FacialImage => 0x02,
            Self::Fingerprint => 0x08,
            Self::Iris => 0x10,
            Self::Voice => 0x04,
            Self::Dna => 0x20,
        }
    }

    fn from_code(value: u8) -> EmrtdDataResult<Self> {
        match value {
            0x02 => Ok(Self::FacialImage),
            0x08 => Ok(Self::Fingerprint),
            0x10 => Ok(Self::Iris),
            0x04 => Ok(Self::Voice),
            0x20 => Ok(Self::Dna),
            _ => Err(EmrtdDataError::Unsupported(format!(
                "unsupported biometric type code: 0x{value:02X}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    Jpeg,
    Jpeg2000,
    Png,
    Bmp,
    Wsq,
}

impl ImageFormat {
    pub fn code(self) -> u8 {
        match self {
            Self::Jpeg => 0x00,
            Self::Jpeg2000 => 0x01,
            Self::Png => 0x02,
            Self::Bmp => 0x03,
            Self::Wsq => 0x04,
        }
    }

    fn from_code(value: u8) -> EmrtdDataResult<Self> {
        match value {
            0x00 => Ok(Self::Jpeg),
            0x01 => Ok(Self::Jpeg2000),
            0x02 => Ok(Self::Png),
            0x03 => Ok(Self::Bmp),
            0x04 => Ok(Self::Wsq),
            _ => Err(EmrtdDataError::Unsupported(format!(
                "unsupported biometric image format: 0x{value:02X}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BiometricHeader {
    pub format_owner: u16,
    pub format_type: u16,
    pub biometric_type: BiometricType,
    pub biometric_subtype: u8,
    pub creation_date: Option<String>,
    pub validity_period: Option<(String, String)>,
    pub creator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FacialImageTemplate {
    pub header: BiometricHeader,
    pub image_format: ImageFormat,
    pub image_width: u16,
    pub image_height: u16,
    pub image_color_space: u16,
    pub source_type: u16,
    pub device_type: u16,
    pub quality: u16,
    pub image_data: Vec<u8>,
    pub feature_points: Option<Vec<(u16, u16)>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FingerprintTemplate {
    pub header: BiometricHeader,
    pub impression_type: u8,
    pub finger_quality: u8,
    pub finger_position: u8,
    pub image_width: u16,
    pub image_height: u16,
    pub resolution_x: u16,
    pub resolution_y: u16,
    pub compression: u8,
    pub minutiae: Vec<serde_json::Value>,
    pub image_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrisTemplate {
    pub header: BiometricHeader,
    pub eye_position: u8,
    pub image_format: ImageFormat,
    pub image_width: u16,
    pub image_height: u16,
    pub image_depth: u8,
    pub range: u16,
    pub roll_angle: u16,
    pub iris_center_x: u16,
    pub iris_center_y: u16,
    pub iris_radius: u16,
    pub image_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "template_type", rename_all = "snake_case")]
pub enum BiometricTemplate {
    Facial(FacialImageTemplate),
    Fingerprint(FingerprintTemplate),
    Iris(IrisTemplate),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityReport {
    pub overall_quality: f64,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}

pub fn parse_biometric_template(
    data: &[u8],
    biometric_type: BiometricType,
) -> EmrtdDataResult<BiometricTemplate> {
    ensure_bounded(data, "biometric template")?;
    match biometric_type {
        BiometricType::FacialImage => parse_facial(data).map(BiometricTemplate::Facial),
        BiometricType::Fingerprint => parse_fingerprint(data).map(BiometricTemplate::Fingerprint),
        BiometricType::Iris => parse_iris(data).map(BiometricTemplate::Iris),
        unsupported => Err(EmrtdDataError::Unsupported(format!(
            "unsupported biometric template type: {unsupported:?}"
        ))),
    }
}

fn parse_common_header(data: &[u8]) -> EmrtdDataResult<BiometricHeader> {
    let header = data
        .get(..COMMON_HEADER_BYTES)
        .ok_or(EmrtdDataError::Truncated("biometric common header"))?;
    Ok(BiometricHeader {
        format_owner: u16::from_be_bytes([header[0], header[1]]),
        format_type: u16::from_be_bytes([header[2], header[3]]),
        biometric_type: BiometricType::from_code(header[4])?,
        biometric_subtype: header[5],
        creation_date: None,
        validity_period: None,
        creator: None,
    })
}

fn require_header_type(header: &BiometricHeader, expected: BiometricType) -> EmrtdDataResult<()> {
    if header.biometric_type != expected {
        return Err(EmrtdDataError::InvalidFormat(format!(
            "biometric header type {:?} does not match requested type {:?}",
            header.biometric_type, expected
        )));
    }
    Ok(())
}

fn parse_facial(data: &[u8]) -> EmrtdDataResult<FacialImageTemplate> {
    const FIELDS: usize = 14;
    let header = parse_common_header(data)?;
    require_header_type(&header, BiometricType::FacialImage)?;
    let fields = data
        .get(COMMON_HEADER_BYTES..COMMON_HEADER_BYTES + FIELDS)
        .ok_or(EmrtdDataError::Truncated("facial image fields"))?;
    let quality = be_u16(fields, 10);
    if quality > 100 {
        return Err(EmrtdDataError::InvalidFormat(
            "facial quality must be between 0 and 100".into(),
        ));
    }
    Ok(FacialImageTemplate {
        header,
        image_width: be_u16(fields, 0),
        image_height: be_u16(fields, 2),
        image_color_space: be_u16(fields, 4),
        source_type: be_u16(fields, 6),
        device_type: be_u16(fields, 8),
        quality,
        image_format: ImageFormat::from_code(fields[12])?,
        image_data: data[COMMON_HEADER_BYTES + FIELDS..].to_vec(),
        feature_points: None,
    })
}

fn parse_fingerprint(data: &[u8]) -> EmrtdDataResult<FingerprintTemplate> {
    const FIELDS: usize = 14;
    let header = parse_common_header(data)?;
    require_header_type(&header, BiometricType::Fingerprint)?;
    let fields = data
        .get(COMMON_HEADER_BYTES..COMMON_HEADER_BYTES + FIELDS)
        .ok_or(EmrtdDataError::Truncated("fingerprint fields"))?;
    if fields[1] > 100 {
        return Err(EmrtdDataError::InvalidFormat(
            "fingerprint quality must be between 0 and 100".into(),
        ));
    }
    let image = data[COMMON_HEADER_BYTES + FIELDS..].to_vec();
    Ok(FingerprintTemplate {
        header,
        impression_type: fields[0],
        finger_quality: fields[1],
        finger_position: fields[2],
        image_width: be_u16(fields, 4),
        image_height: be_u16(fields, 6),
        resolution_x: be_u16(fields, 8),
        resolution_y: be_u16(fields, 10),
        compression: fields[12],
        minutiae: Vec::new(),
        image_data: (!image.is_empty()).then_some(image),
    })
}

fn parse_iris(data: &[u8]) -> EmrtdDataResult<IrisTemplate> {
    const FIELDS: usize = 17;
    let header = parse_common_header(data)?;
    require_header_type(&header, BiometricType::Iris)?;
    let fields = data
        .get(COMMON_HEADER_BYTES..COMMON_HEADER_BYTES + FIELDS)
        .ok_or(EmrtdDataError::Truncated("iris fields"))?;
    Ok(IrisTemplate {
        header,
        eye_position: fields[0],
        image_format: ImageFormat::from_code(fields[1])?,
        image_width: be_u16(fields, 2),
        image_height: be_u16(fields, 4),
        image_depth: fields[6],
        range: be_u16(fields, 7),
        roll_angle: be_u16(fields, 9),
        iris_center_x: be_u16(fields, 11),
        iris_center_y: be_u16(fields, 13),
        iris_radius: be_u16(fields, 15),
        image_data: data[COMMON_HEADER_BYTES + FIELDS..].to_vec(),
    })
}

pub fn validate_template_quality(template: &BiometricTemplate) -> QualityReport {
    match template {
        BiometricTemplate::Facial(template) => {
            let mut report = QualityReport::new(f64::from(template.quality) / 100.0);
            if template.image_width < 240 || template.image_height < 320 {
                report.issue(
                    "Image resolution below ICAO recommendations",
                    "Use higher resolution image (min 240x320)",
                );
                report.overall_quality *= 0.8;
            }
            if !matches!(
                template.image_format,
                ImageFormat::Jpeg | ImageFormat::Jpeg2000
            ) {
                report.issue("Non-standard image format", "Use JPEG or JPEG2000 format");
            }
            report
        }
        BiometricTemplate::Fingerprint(template) => {
            let mut report = QualityReport::new(f64::from(template.finger_quality) / 100.0);
            if template.resolution_x < 500 || template.resolution_y < 500 {
                report.issue(
                    "Resolution below FBI standards (500 ppi)",
                    "Use 500+ ppi resolution for fingerprints",
                );
                report.overall_quality *= 0.7;
            }
            if template.minutiae.len() < 12 {
                report.issue(
                    "Insufficient minutiae points for reliable matching",
                    "Capture more minutiae points (minimum 12)",
                );
                report.overall_quality *= 0.6;
            }
            report
        }
        BiometricTemplate::Iris(template) => {
            let mut report = QualityReport::new(0.8);
            if template.image_width < 640 || template.image_height < 480 {
                report.issue(
                    "Iris image resolution below recommended standards",
                    "Use higher resolution for iris capture",
                );
                report.overall_quality *= 0.8;
            }
            if template.iris_radius < 50 {
                report.issue(
                    "Iris appears too small in image",
                    "Move closer to capture device",
                );
                report.overall_quality *= 0.7;
            }
            report
        }
    }
}

impl QualityReport {
    fn new(overall_quality: f64) -> Self {
        Self {
            overall_quality,
            issues: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    fn issue(&mut self, issue: &str, recommendation: &str) {
        self.issues.push(issue.into());
        self.recommendations.push(recommendation.into());
    }
}

fn be_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}
