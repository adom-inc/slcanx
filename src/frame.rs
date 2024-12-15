use embedded_can::Id;
use heapless::Vec;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{
    codec::{
        bytes_to_hex, dec_digit_to_u8, extended_id_from_hex, extended_id_to_hex, hex_digit_to_u8,
        standard_id_from_hex, standard_id_to_hex, to_hex_digit, unpack_data_bytes,
    },
    MAX_MESSAGE_DATA_SIZE,
};

/// A joint enum which can hold either a CAN 2.0 frame or a CAN FD frame. See
/// [`Can2Frame`] and [`CanFdFrame`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CanFrame {
    Can2(Can2Frame),
    CanFd(CanFdFrame),
}

impl From<Can2Frame> for CanFrame {
    fn from(frame: Can2Frame) -> Self {
        Self::Can2(frame)
    }
}

impl From<CanFdFrame> for CanFrame {
    fn from(frame: CanFdFrame) -> Self {
        Self::CanFd(frame)
    }
}

impl CanFrame {
    pub fn id(&self) -> Id {
        match self {
            CanFrame::Can2(can2_frame) => can2_frame.id,
            CanFrame::CanFd(can_fd_frame) => can_fd_frame.id,
        }
    }

    pub fn format(&self) -> FrameFormat {
        match self {
            CanFrame::Can2(Can2Frame { data: Some(_), .. }) => FrameFormat::Normal,
            CanFrame::Can2(Can2Frame { data: None, .. }) => FrameFormat::Remote,
            CanFrame::CanFd(CanFdFrame {
                bit_rate_switched: false,
                ..
            }) => FrameFormat::FdNoBrs,
            CanFrame::CanFd(CanFdFrame {
                bit_rate_switched: true,
                ..
            }) => FrameFormat::FdWithBrs,
        }
    }

    /// Slice over the full data of the frame (None for RTR frames)
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            CanFrame::Can2(can2_frame) => can2_frame.data(),
            CanFrame::CanFd(can_fd_frame) => Some(can_fd_frame.data()),
        }
    }

    pub fn is_fd(&self) -> bool {
        match self {
            CanFrame::Can2(_) => false,
            CanFrame::CanFd(_) => true,
        }
    }

    /// The full length of the data payload or the DLC for RTR frames (not necessarily equal
    /// to the DLC for FD frames)
    pub fn data_len(&self) -> usize {
        match self {
            CanFrame::Can2(frame) => frame.dlc(),
            CanFrame::CanFd(frame) => frame.dlc().get_num_bytes(),
        }
    }

    /// The actual compressed value sent in the CAN frame (not necessarily equal
    /// to the data length for FD frames)
    pub fn dlc(&self) -> u8 {
        match self {
            CanFrame::Can2(frame) => frame.dlc() as u8,
            CanFrame::CanFd(frame) => frame.dlc() as u8,
        }
    }
}

/// Represents a CAN 2.0 frame which supports RTR (Remote Transmission Request).
///
/// The DLC can be up to 8 bytes, and the data if absent means that it is an
/// RTR frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Can2Frame {
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    id: Id,
    dlc: usize,
    data: Option<[u8; 8]>,
}

impl Can2Frame {
    /// Creates a new CAN 2.0 data frame. `data` must have a length in the
    /// range 0..=8 or else `None` will be returned instead.
    pub fn new_data(id: impl Into<Id>, data: &[u8]) -> Option<Self> {
        if data.len() > 8 {
            return None;
        }

        let mut copy = [0u8; 8];
        copy[..data.len()].copy_from_slice(data);

        Some(Self {
            id: id.into(),
            dlc: data.len(),
            data: Some(copy),
        })
    }

    /// Creates a new CAN 2.0 data frame. `dlc` must be in the range 0..=8 or
    /// else `None` will be returned instead.
    pub fn new_remote(id: impl Into<Id>, dlc: usize) -> Option<Self> {
        if dlc > 8 {
            return None;
        }

        Some(Self {
            id: id.into(),
            dlc,
            data: None,
        })
    }

    /// Gets the message ID of the frame
    pub fn id(&self) -> Id {
        self.id
    }

    /// Gets the DLC (Data Length Code) of the frame
    pub fn dlc(&self) -> usize {
        self.dlc
    }

    /// Gets the data associated with the frame. Will return `None` if it is an
    /// RTR frame.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_ref().map(|d| &d[..self.dlc])
    }

    pub fn is_remote(&self) -> bool {
        self.data.is_none()
    }
}

/// Represents all the possible DLC values for CAN FD frames.
///
/// The integer value of the enum maps to the DLC used in the CAN protocol and
/// not the actual number of bytes associated with each variant. To obtain
/// that, see [`FdDataLengthCode::get_num_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum FdDataLengthCode {
    Bytes0 = 0,
    Bytes1 = 1,
    Bytes2 = 2,
    Bytes3 = 3,
    Bytes4 = 4,
    Bytes5 = 5,
    Bytes6 = 6,
    Bytes7 = 7,
    Bytes8 = 8,
    Bytes12 = 9,
    Bytes16 = 10,
    Bytes20 = 11,
    Bytes24 = 12,
    Bytes32 = 13,
    Bytes48 = 14,
    Bytes64 = 15,
}

impl FdDataLengthCode {
    /// Returns the next closest DLC for the given length value. Values over 64
    /// will return `None`.
    pub fn for_length(length: usize) -> Option<Self> {
        Some(match length {
            x @ 0..=8 => (x as u8).try_into().unwrap(),
            9..=12 => Self::Bytes12,
            13..=16 => Self::Bytes16,
            17..=20 => Self::Bytes20,
            21..=24 => Self::Bytes24,
            25..=32 => Self::Bytes32,
            33..=48 => Self::Bytes48,
            49..=64 => Self::Bytes64,
            _ => return None,
        })
    }

    /// Returns the number of bytes that this variant can hold, which is
    /// different from the enum's integer value.
    pub fn get_num_bytes(&self) -> usize {
        match self {
            Self::Bytes0 => 0,
            Self::Bytes1 => 1,
            Self::Bytes2 => 2,
            Self::Bytes3 => 3,
            Self::Bytes4 => 4,
            Self::Bytes5 => 5,
            Self::Bytes6 => 6,
            Self::Bytes7 => 7,
            Self::Bytes8 => 8,
            Self::Bytes12 => 12,
            Self::Bytes16 => 16,
            Self::Bytes20 => 20,
            Self::Bytes24 => 24,
            Self::Bytes32 => 32,
            Self::Bytes48 => 48,
            Self::Bytes64 => 64,
        }
    }
}

/// Represents a CAN FD frame which can store up to 64 data bytes and
/// optionally supports transmitting at a higher data bit rate (this defaults
/// to true). See [`DataBitRate`](crate::DataBitRate).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CanFdFrame {
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    id: Id,
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    data: heapless::Vec<u8, 64>,
    bit_rate_switched: bool,
}

impl CanFdFrame {
    /// Creates a new CAN FD frame. Will return `None` if the data is not one
    /// of the allowed DLC values for CAN FD.
    pub fn new(id: impl Into<Id>, data: &[u8]) -> Option<Self> {
        FdDataLengthCode::for_length(data.len())?;

        Some(Self {
            id: id.into(),
            data: heapless::Vec::<u8, 64>::from_slice(data).unwrap(),
            bit_rate_switched: true,
        })
    }

    /// Creates a new CAN FD frame. Will return `None` if the data is longer
    /// than 64 bytes. Any lengths under 64 will be padded with 0s until they
    /// reach one of the allowed CAN FD data length codes.
    pub fn new_padded(id: impl Into<Id>, data: &[u8]) -> Option<Self> {
        let dlc = FdDataLengthCode::for_length(data.len())?;

        let mut data = heapless::Vec::<u8, 64>::from_slice(data).unwrap();
        data.extend((data.len()..dlc.get_num_bytes()).map(|_| 0));

        Some(Self {
            id: id.into(),
            data,
            bit_rate_switched: true,
        })
    }

    /// Gets the message ID of the frame
    pub fn id(&self) -> Id {
        self.id
    }

    /// Gets the DLC (Data Length Code) of the frame
    pub fn dlc(&self) -> FdDataLengthCode {
        FdDataLengthCode::for_length(self.data.len()).unwrap()
    }

    /// Gets the data associated with the frame (length will match DLC)
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns whether or not this frame should be/was transmitted with the
    /// higher data bit rate
    pub fn is_bit_rate_switched(&self) -> bool {
        self.bit_rate_switched
    }

    /// Sets whether the frame should be transmitted with the higher data bit
    /// rate
    pub fn set_bit_rate_switched(&mut self, bit_rate_switched: bool) {
        self.bit_rate_switched = bit_rate_switched
    }

    /// Consumes self and returns a new self with the the supplied value for
    /// `bit_rate_switched`
    pub fn with_bit_rate_switched(mut self, bit_rate_switched: bool) -> Self {
        self.bit_rate_switched = bit_rate_switched;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameParseError {
    /* Frame Parsing */
    #[error("Tried to decode ID kind but it was invalid ({0:?})")]
    InvalidIdKind(u8),
    #[error("Tried to decode a hex digit but it was out of range ({0:?})")]
    IllegalHexDigit(u8),
    #[error("Received a CAN Standard ID ({0:?}) that was out of the valid range (0..=0x7FF)")]
    StandardIdOutOfRange(u16),
    #[error("Received a CAN Extended ID ({0:?}) that was out of the valid range (0..=0x1FFFFFFF)")]
    ExtendedIdOutOfRange(u32),
    #[error("Tried to decode frame format but it was invalid ({0:?})")]
    InvalidFrameFormat(u8),
    #[error("Tried to decode a decimal digit but it was out of range ({0:?})")]
    IllegalDecimalDigit(u8),
    #[error("Received a CAN 2 DLC ({0:?}) that was out of the valid range (0..=8)")]
    InvalidCan2DataLengthCode(u8),
    #[error("Received encoded data with a length ({0:?}) that was not a multiple of 2")]
    InvalidEncodedDataLength(u8),
    #[error("Received a frame with expected length ({0:?}) but ({1:?}) bytes of data")]
    MismatchedDataLength(u8, usize),
    #[error("Received a remote frame with ({0:?}) bytes of additional data (should be empty)")]
    DataInRemoteFrame(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = FrameParseError, constructor = FrameParseError::InvalidIdKind))]
#[repr(u8)]
pub enum IdKind {
    #[default]
    Standard = b'S',
    Extended = b'E',
}

pub trait IdExt {
    fn kind(self) -> IdKind;
}

impl IdExt for Id {
    fn kind(self) -> IdKind {
        match self {
            Id::Standard(_) => IdKind::Standard,
            Id::Extended(_) => IdKind::Extended,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = FrameParseError, constructor = FrameParseError::InvalidFrameFormat))]
#[repr(u8)]
pub enum FrameFormat {
    #[default]
    Normal = b'N',
    Remote = b'R',
    FdNoBrs = b'F',
    FdWithBrs = b'B',
}

impl CanFrame {
    pub fn from_bytes(buffer: &[u8]) -> Result<Self, FrameParseError> {
        let id_kind: IdKind = buffer[0].try_into()?;

        let (id, remaining) = match id_kind {
            IdKind::Standard => (
                Id::Standard(standard_id_from_hex(buffer[1..4].try_into().unwrap())?),
                &buffer[4..],
            ),
            IdKind::Extended => (
                Id::Extended(extended_id_from_hex(buffer[1..9].try_into().unwrap())?),
                &buffer[9..],
            ),
        };

        let format: FrameFormat = remaining[0].try_into()?;
        let dlc_byte = remaining[1];
        let encoded_data_bytes = &remaining[2..];

        Ok(match format {
            FrameFormat::Normal => {
                let dlc = dec_digit_to_u8(dlc_byte)?;

                if dlc > 8 {
                    return Err(FrameParseError::InvalidCan2DataLengthCode(dlc));
                }

                let data = unpack_data_bytes(encoded_data_bytes, dlc as usize)?;

                Self::Can2(Can2Frame::new_data(id, &data).unwrap())
            }
            FrameFormat::Remote => {
                let dlc = dec_digit_to_u8(dlc_byte)?;

                if dlc > 8 {
                    return Err(FrameParseError::InvalidCan2DataLengthCode(dlc));
                }

                if !encoded_data_bytes.is_empty() {
                    return Err(FrameParseError::DataInRemoteFrame(encoded_data_bytes.len()));
                }

                Self::Can2(Can2Frame::new_remote(id, dlc as usize).unwrap())
            }
            FrameFormat::FdNoBrs => {
                let dlc = FdDataLengthCode::try_from(hex_digit_to_u8(dlc_byte)?).unwrap();
                let data = unpack_data_bytes(encoded_data_bytes, dlc.get_num_bytes())?;

                CanFdFrame::new(id, &data)
                    .unwrap()
                    .with_bit_rate_switched(false)
                    .into()
            }
            FrameFormat::FdWithBrs => {
                let dlc = FdDataLengthCode::try_from(hex_digit_to_u8(dlc_byte)?).unwrap();
                let data = unpack_data_bytes(encoded_data_bytes, dlc.get_num_bytes())?;

                CanFdFrame::new(id, &data).unwrap().into()
            }
        })
    }

    pub fn as_bytes(&self) -> Vec<u8, MAX_MESSAGE_DATA_SIZE> {
        let mut result = Vec::new();

        let id = self.id();

        result.push(id.kind().into()).unwrap();

        match id {
            Id::Standard(standard_id) => result
                .extend_from_slice(&standard_id_to_hex(standard_id))
                .unwrap(),
            Id::Extended(extended_id) => result
                .extend_from_slice(&extended_id_to_hex(extended_id))
                .unwrap(),
        }

        result.push(self.format().into()).unwrap();

        result
            .push(match self {
                CanFrame::Can2(can2_frame) => to_hex_digit(can2_frame.dlc as u32),
                CanFrame::CanFd(can_fd_frame) => to_hex_digit(can_fd_frame.data.len() as u32),
            })
            .unwrap();

        if let Some(data) = self.data() {
            result.extend_from_slice(&bytes_to_hex(data)).unwrap();
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use embedded_can::{ExtendedId, StandardId};
    use heapless::Vec;

    use crate::{Can2Frame, CanFdFrame, CanFrame, FrameParseError};

    fn remove_whitespace(data: &[u8]) -> Vec<u8, 256> {
        Vec::from_iter(data.iter().filter(|b| !b.is_ascii_whitespace()).copied())
    }

    #[test]
    fn frame_parse_errors() {
        /* ID kind parsing */

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"A")),
            Err(FrameParseError::InvalidIdKind(b'A'))
        );

        /* ID parsing */

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S FFG")),
            Err(FrameParseError::IllegalHexDigit(b'G'))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S FFF")),
            Err(FrameParseError::StandardIdOutOfRange(0xFFF))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"E 2FFFFFFF")),
            Err(FrameParseError::ExtendedIdOutOfRange(0x2FFFFFFF))
        );

        /* Frame format parsing */

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 A")),
            Err(FrameParseError::InvalidFrameFormat(b'A'))
        );

        /* DLC Parsing */

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N A")),
            Err(FrameParseError::IllegalDecimalDigit(b'A'))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 9")),
            Err(FrameParseError::InvalidCan2DataLengthCode(9))
        );

        /* Data parsing */

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 0 1")),
            Err(FrameParseError::InvalidEncodedDataLength(1))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 1 GG")),
            Err(FrameParseError::IllegalHexDigit(b'G'))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 0 12")),
            Err(FrameParseError::MismatchedDataLength(0, 1))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 1 12 34")),
            Err(FrameParseError::MismatchedDataLength(1, 2))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 8 00 01 02 03 04 05 06 07 08")),
            Err(FrameParseError::MismatchedDataLength(8, 9))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 8 00 01 02 03")),
            Err(FrameParseError::MismatchedDataLength(8, 4))
        );

        /* Remote data check */

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 R 1 00")),
            Err(FrameParseError::DataInRemoteFrame(2))
        );

        /* FD DLC */

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 F G")),
            Err(FrameParseError::IllegalHexDigit(b'G'))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 B G")),
            Err(FrameParseError::IllegalHexDigit(b'G'))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 F 9  00 01 02 03 04 05 06 07")),
            Err(FrameParseError::MismatchedDataLength(12, 8))
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 F 9  00 01 02 03 04 05 06 07 08")),
            Err(FrameParseError::MismatchedDataLength(12, 9))
        );
    }

    #[test]
    fn parse_normal_frames() {
        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 N 8  00 01 02 03 04 05 06 07")),
            Ok(
                Can2Frame::new_data(StandardId::ZERO, &[0, 1, 2, 3, 4, 5, 6, 7])
                    .unwrap()
                    .into()
            )
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 7FF N 3  00 01 02")),
            Ok(Can2Frame::new_data(StandardId::MAX, &[0, 1, 2,])
                .unwrap()
                .into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 7FF N 0")),
            Ok(Can2Frame::new_data(StandardId::MAX, &[]).unwrap().into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"E 1FFFFFFF N 0")),
            Ok(Can2Frame::new_data(ExtendedId::MAX, &[]).unwrap().into())
        );
    }

    #[test]
    fn parse_remote_frames() {
        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 R 8")),
            Ok(Can2Frame::new_remote(StandardId::ZERO, 8).unwrap().into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 7FF R 3")),
            Ok(Can2Frame::new_remote(StandardId::MAX, 3).unwrap().into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 7FF R 0")),
            Ok(Can2Frame::new_remote(StandardId::MAX, 0).unwrap().into())
        );
    }
    #[test]
    fn parse_fd_frames() {
        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 F 8  00 01 02 03 04 05 06 07")),
            Ok(CanFdFrame::new(StandardId::ZERO, &[0, 1, 2, 3, 4, 5, 6, 7])
                .unwrap()
                .with_bit_rate_switched(false)
                .into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 7FF F 3  00 01 02")),
            Ok(CanFdFrame::new(StandardId::MAX, &[0, 1, 2,])
                .unwrap()
                .with_bit_rate_switched(false)
                .into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 7FF F 0")),
            Ok(CanFdFrame::new(StandardId::MAX, &[])
                .unwrap()
                .with_bit_rate_switched(false)
                .into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"E 1FFFFFFF F 0")),
            Ok(CanFdFrame::new(ExtendedId::MAX, &[])
                .unwrap()
                .with_bit_rate_switched(false)
                .into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(
                b"S 000 F 9  00 01 02 03 04 05 06 07 08 09 0A 0B"
            )),
            Ok(
                CanFdFrame::new(StandardId::ZERO, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
                    .unwrap()
                    .with_bit_rate_switched(false)
                    .into()
            )
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(b"S 000 F F  0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000")),
            Ok(CanFdFrame::new(StandardId::ZERO, &[0, 0, 0, 0, 0, 0, 0, 0].repeat(8))
                .unwrap()
                .with_bit_rate_switched(false)
                .into())
        );

        assert_eq!(
            CanFrame::from_bytes(&remove_whitespace(
                b"S 000 B 9  00 01 02 03 04 05 06 07 08 09 0A 0B"
            )),
            Ok(
                CanFdFrame::new(StandardId::ZERO, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
                    .unwrap()
                    .with_bit_rate_switched(true)
                    .into()
            )
        );
    }
}
