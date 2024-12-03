use heapless::Vec;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{frame::CanFrame, FrameParseError, MAX_MESSAGE_DATA_SIZE, MAX_MESSAGE_SIZE};

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Command {
    SetNominalBitrate(NominalBitRate),
    SetDataBitrate(DataBitRate),
    SetOperatingMode(OperatingMode),
    SetAutoRetransmissionMode(AutoRetransmissionMode),
    Open,
    Close,
    TransmitFrame(CanFrame),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = CommandParseError, constructor = CommandParseError::UnrecognizedCommand))]
#[repr(u8)]
pub enum CommandKind {
    SetNominalBitrate = b'B',
    SetDataBitrate = b'D',
    SetOperatingMode = b'M',
    SetAutoRetransmissionMode = b'A',
    Open = b'O',
    Close = b'C',
    TransmitFrame = b'T',
}

impl CommandKind {
    const fn get_min_data_length(&self) -> usize {
        match self {
            Self::SetNominalBitrate => 1,
            Self::SetDataBitrate => 1,
            Self::SetOperatingMode => 1,
            Self::SetAutoRetransmissionMode => 1,
            Self::Open => 0,
            Self::Close => 0,
            Self::TransmitFrame => 1 + 3 + 1 + 1, // (id kind + standard id + remote + dlc)
        }
    }

    const fn get_max_data_length(&self) -> usize {
        match self {
            Self::SetNominalBitrate => 1,
            Self::SetDataBitrate => 1,
            Self::SetOperatingMode => 1,
            Self::SetAutoRetransmissionMode => 1,
            Self::Open => 0,
            Self::Close => 0,
            Self::TransmitFrame => MAX_MESSAGE_DATA_SIZE,
        }
    }
}

/// The bit rate used for CAN 2.0 frames, CAN FD frames without BRS, and the
/// message ID arbitration for CAN FD frames with BRS
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = CommandParseError, constructor = CommandParseError::InvalidNominalBitrate))]
#[repr(u8)]
pub enum NominalBitRate {
    /// Transmits and receives at 10 Kbit/s
    Rate10Kbit = b'0',
    /// Transmits and receives at 20 Kbit/s
    Rate20Kbit = b'1',
    /// Transmits and receives at 50 Kbit/s
    Rate50Kbit = b'2',
    /// Transmits and receives at 100 Kbit/s
    Rate100Kbit = b'3',
    /// Transmits and receives at 125 Kbit/s
    Rate125Kbit = b'4',
    /// Transmits and receives at 250 Kbit/s
    Rate250Kbit = b'5',
    /// Transmits and receives at 500 Kbit/s
    Rate500Kbit = b'6',
    /// Transmits and receives at 800 Kbit/s
    Rate800Kbit = b'7',
    /// Transmits and receives at 1 Mbit/s
    Rate1Mbit = b'8',
    /// Transmits and receives at 83.3 Kbit/s
    Rate83_3Kbit = b'9',
}

/// The bit rate used for the data and CRC sections of CAN FD frames with BRS
/// enabled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = CommandParseError, constructor = CommandParseError::InvalidDataBitrate))]
#[repr(u8)]
pub enum DataBitRate {
    /// Transmits and receives at 2 Mbit/s
    #[default]
    Rate2Mbit = b'2',
    /// Transmits and receives at 5 Mbit/s
    Rate5Mbit = b'5',
}

/// Operating mode of the gateway which changes its fundamental behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = CommandParseError, constructor = CommandParseError::InvalidOperatingMode))]
#[repr(u8)]
pub enum OperatingMode {
    /// Default mode where the gateway can send and receive frames on the bus
    #[default]
    NormalCanFD = b'F',
    NormalCan2 = b'2',
    InternalLoopback = b'I',
    ExternalLoopback = b'E',
    ListenOnly = b'L',
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = CommandParseError, constructor = CommandParseError::InvalidAutoRetransmissionMode))]
#[repr(u8)]
pub enum AutoRetransmissionMode {
    Disabled = b'0',
    ThreeRetries = b'3',
    #[default]
    UnlimitedRetries = b'U',
}

impl Command {
    fn get_kind(&self) -> CommandKind {
        match self {
            Self::SetNominalBitrate(_) => CommandKind::SetNominalBitrate,
            Self::SetDataBitrate(_) => CommandKind::SetDataBitrate,
            Self::SetOperatingMode(_) => CommandKind::SetOperatingMode,
            Self::SetAutoRetransmissionMode(_) => CommandKind::SetAutoRetransmissionMode,
            Self::Open => CommandKind::Open,
            Self::Close => CommandKind::Close,
            Self::TransmitFrame(_) => CommandKind::TransmitFrame,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8, MAX_MESSAGE_SIZE> {
        let mut result = Vec::new();

        result.push(self.get_kind().into()).unwrap();

        match self {
            Self::SetNominalBitrate(nominal_bit_rate) => {
                result.push((*nominal_bit_rate).into()).unwrap();
            }
            Self::SetDataBitrate(data_bit_rate) => {
                result.push((*data_bit_rate).into()).unwrap();
            }
            Self::SetOperatingMode(operating_mode) => {
                result.push((*operating_mode).into()).unwrap();
            }
            Self::SetAutoRetransmissionMode(auto_retransmission_mode) => {
                result.push((*auto_retransmission_mode).into()).unwrap();
            }
            Self::Open => {}
            Self::Close => {}
            Self::TransmitFrame(can_frame) => {
                result.extend_from_slice(&can_frame.as_bytes()).unwrap();
            }
        }

        result
    }
}

/// Various errors which can arise while parsing an SLCANX message
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandParseError {
    /* Generic message parsing */
    #[error("Tried to parse an empty buffer")]
    Empty,
    #[error("Received a command with an unrecognized specifier ({0:?})")]
    UnrecognizedCommand(u8),
    #[error("Received a command ({0:?}) but less bytes than is required to parse it ({1:?})")]
    NotEnoughBytes(CommandKind, usize),
    #[error("Received a command ({0:?}) but more bytes than were expected ({1:?})")]
    TooManyBytes(CommandKind, usize),

    /* Option Parsing */
    #[error("Tried to decode nominal bitrate but it was invalid ({0:?})")]
    InvalidNominalBitrate(u8),
    #[error("Tried to decode data bitrate but it was invalid ({0:?})")]
    InvalidDataBitrate(u8),
    #[error("Tried to decode operating mode but it was invalid ({0:?})")]
    InvalidOperatingMode(u8),
    #[error("Tried to decode auto retransmission mode but it was invalid ({0:?})")]
    InvalidAutoRetransmissionMode(u8),

    /* Frame Parsing */
    #[error("Failed to parse frame content")]
    InvalidFrameContent(#[from] FrameParseError),
}

impl Command {
    pub fn from_bytes(buffer: &[u8]) -> Result<Self, CommandParseError> {
        if buffer.is_empty() {
            return Err(CommandParseError::Empty);
        }

        let kind: CommandKind = buffer[0].try_into()?;
        let command_data = &buffer[1..];

        /* Validate data length */

        if command_data.len() < kind.get_min_data_length() {
            return Err(CommandParseError::NotEnoughBytes(kind, buffer.len()));
        }

        if command_data.len() > kind.get_max_data_length() {
            return Err(CommandParseError::TooManyBytes(kind, buffer.len()));
        }

        /* Parse data bytes */

        Ok(match kind {
            CommandKind::SetNominalBitrate => Self::SetNominalBitrate(command_data[0].try_into()?),
            CommandKind::SetDataBitrate => Self::SetDataBitrate(command_data[0].try_into()?),
            CommandKind::SetOperatingMode => Self::SetOperatingMode(command_data[0].try_into()?),
            CommandKind::SetAutoRetransmissionMode => {
                Self::SetAutoRetransmissionMode(command_data[0].try_into()?)
            }
            CommandKind::Open => Self::Open,
            CommandKind::Close => Self::Close,
            CommandKind::TransmitFrame => Self::TransmitFrame(CanFrame::from_bytes(command_data)?),
        })
    }
}
