use core::str::Utf8Error;

use heapless::{String, Vec};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{frame::CanFrame, FrameParseError, MAX_MESSAGE_DATA_SIZE, MAX_MESSAGE_SIZE};

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event {
    /// Device firmware version
    FirmwareVersion(
        #[cfg_attr(feature = "defmt", defmt(Debug2Format))] String<{ MAX_MESSAGE_DATA_SIZE }>,
    ),
    /// Tried to configure the device while the socket is open (not in config mode)
    ConfigurationNotAllowed,
    /// Received an invalid message on the bus
    InvalidMessage,
    /// Failed to TX a user requested message
    TransmissionError(TransmissionErrorKind),
    /// The reception FIFO overflowed and the socket closed itself
    RxFifoOverflow,
    /// Received a frame from the bus
    ReceivedFrame(CanFrame),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = EventParseError, constructor = EventParseError::UnrecognizedEvent))]
#[repr(u8)]
pub enum EventKind {
    FirmwareVersion = b'V',
    ConfigurationNotAllowed = b'C',
    InvalidMessage = b'I',
    TransmissionError = b'E',
    RxFifoOverflow = b'O',
    ReceivedFrame = b'R',
}

impl EventKind {
    const fn get_min_data_length(&self) -> usize {
        match self {
            Self::FirmwareVersion => 5, // 0.0.0
            Self::ConfigurationNotAllowed => 0,
            Self::InvalidMessage => 0,
            Self::TransmissionError => 1,
            Self::RxFifoOverflow => 0,
            Self::ReceivedFrame => 1 + 3 + 1 + 1, // (id kind + standard id + remote + dlc)
        }
    }

    const fn get_max_data_length(&self) -> usize {
        match self {
            Self::FirmwareVersion => 5 + 1 + 5 + 1 + 5, // 65535.65535.65535
            Self::ConfigurationNotAllowed => 0,
            Self::InvalidMessage => 0,
            Self::TransmissionError => 1,
            Self::RxFifoOverflow => 0,
            Self::ReceivedFrame => MAX_MESSAGE_DATA_SIZE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = EventParseError, constructor = EventParseError::InvalidTransmissionErrorKind))]
#[repr(u8)]
pub enum TransmissionErrorKind {
    /// Tried to transmit a message before opening the CAN socket
    SocketClosed = b'C',
    /// Reached the retransmission threshold for a particular frame
    /// TODO: add ID in event
    RetransmissionAttemptsExhausted = b'R',
}

impl Event {
    fn get_kind(&self) -> EventKind {
        match self {
            Self::FirmwareVersion(_) => EventKind::FirmwareVersion,
            Self::ConfigurationNotAllowed => EventKind::ConfigurationNotAllowed,
            Self::InvalidMessage => EventKind::InvalidMessage,
            Self::TransmissionError(_) => EventKind::TransmissionError,
            Self::RxFifoOverflow => EventKind::RxFifoOverflow,
            Self::ReceivedFrame(_) => EventKind::ReceivedFrame,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8, MAX_MESSAGE_SIZE> {
        let mut result = Vec::new();

        result.push(self.get_kind().into()).unwrap();

        match self {
            Self::FirmwareVersion(string) => {
                result.extend_from_slice(string.as_bytes()).unwrap();
            }
            Self::ConfigurationNotAllowed => {}
            Self::InvalidMessage => {}
            Self::TransmissionError(transmission_error_kind) => {
                result.push((*transmission_error_kind).into()).unwrap();
            }
            Self::RxFifoOverflow => {}
            Self::ReceivedFrame(can_frame) => {
                result.extend_from_slice(&can_frame.as_bytes()).unwrap();
            }
        }

        result
    }
}

/// Various errors which can arise while parsing an SLCANX message
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EventParseError {
    /* Generic message parsing */
    #[error("Tried to parse an empty buffer")]
    Empty,
    #[error("Received an event with an unrecognized specifier ({0:?})")]
    UnrecognizedEvent(u8),
    #[error("Received an event ({0:?}) but less bytes than is required to parse it ({1:?})")]
    NotEnoughBytes(EventKind, usize),
    #[error("Received an event ({0:?}) but more bytes than were expected ({1:?})")]
    TooManyBytes(EventKind, usize),

    /* Option Parsing */
    #[error("Tried to decode transmission error kind but it was invalid ({0:?})")]
    InvalidTransmissionErrorKind(u8),
    #[error("Tried to decode firmware version as UTF-8 but it was invalid ({0:?})")]
    InvalidUtf8(
        #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
        #[from]
        Utf8Error,
    ),

    /* Frame Parsing */
    #[error("Failed to parse frame content")]
    InvalidFrameContent(#[from] FrameParseError),
}

impl Event {
    pub fn from_bytes(buffer: &[u8]) -> Result<Self, EventParseError> {
        if buffer.is_empty() {
            return Err(EventParseError::Empty);
        }

        let kind: EventKind = buffer[0].try_into()?;
        let event_data: Vec<u8, MAX_MESSAGE_DATA_SIZE> = Vec::from_slice(&buffer[1..]).unwrap();

        /* Validate data length */

        if event_data.len() < kind.get_min_data_length() {
            return Err(EventParseError::NotEnoughBytes(kind, buffer.len()));
        }

        if event_data.len() > kind.get_max_data_length() {
            return Err(EventParseError::TooManyBytes(kind, buffer.len()));
        }

        /* Parse data bytes */

        Ok(match kind {
            EventKind::FirmwareVersion => Self::FirmwareVersion(String::from_utf8(event_data)?),
            EventKind::ConfigurationNotAllowed => Self::ConfigurationNotAllowed,
            EventKind::InvalidMessage => Self::InvalidMessage,
            EventKind::TransmissionError => Self::TransmissionError(event_data[0].try_into()?),
            EventKind::RxFifoOverflow => Self::RxFifoOverflow,
            EventKind::ReceivedFrame => Self::ReceivedFrame(CanFrame::from_bytes(&event_data)?),
        })
    }
}
