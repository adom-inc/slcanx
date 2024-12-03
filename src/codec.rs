use embedded_can::{ExtendedId, StandardId};
use heapless::Vec;

use crate::{FrameParseError, MAX_DECODED_DATA_LENGTH, MAX_ENCODED_DATA_LENGTH};

/* Encoding */

pub fn to_hex_digit(value: u32) -> u8 {
    const HEX_LUT: &[u8] = "0123456789ABCDEF".as_bytes();

    HEX_LUT[(value & 0xF) as usize]
}

pub fn standard_id_to_hex(id: StandardId) -> [u8; 3] {
    let raw = id.as_raw() as u32;

    [
        to_hex_digit(raw >> 8),
        to_hex_digit(raw >> 4),
        to_hex_digit(raw),
    ]
}

pub fn extended_id_to_hex(id: ExtendedId) -> [u8; 8] {
    let raw = id.as_raw();

    [
        to_hex_digit(raw >> 28),
        to_hex_digit(raw >> 24),
        to_hex_digit(raw >> 20),
        to_hex_digit(raw >> 16),
        to_hex_digit(raw >> 12),
        to_hex_digit(raw >> 8),
        to_hex_digit(raw >> 4),
        to_hex_digit(raw),
    ]
}

pub fn bytes_to_hex(data: &[u8]) -> Vec<u8, MAX_ENCODED_DATA_LENGTH> {
    let mut buf = Vec::new();

    for byte in data {
        buf.push(to_hex_digit((byte >> 4) as u32))
            .expect("Failed to push to Vec");
        buf.push(to_hex_digit(*byte as u32))
            .expect("Failed to push to Vec");
    }

    buf
}

/* Decoding */

pub fn hex_digit_to_u8(byte: u8) -> Result<u8, FrameParseError> {
    Ok(match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => return Err(FrameParseError::IllegalHexDigit(byte)),
    })
}

pub fn dec_digit_to_u8(byte: u8) -> Result<u8, FrameParseError> {
    Ok(match byte {
        b'0'..=b'9' => byte - b'0',
        _ => return Err(FrameParseError::IllegalDecimalDigit(byte)),
    })
}

pub fn u8_from_hex_nibbles(hex_nibbles: &[u8; 2]) -> Result<u8, FrameParseError> {
    let msn = hex_digit_to_u8(hex_nibbles[0])?;
    let lsn = hex_digit_to_u8(hex_nibbles[1])?;

    Ok((msn << 4) | lsn)
}

pub fn standard_id_from_hex(hex_nibbles: &[u8; 3]) -> Result<StandardId, FrameParseError> {
    let mut value = 0u16;

    for nibble in hex_nibbles.iter() {
        value <<= 4;
        value |= hex_digit_to_u8(*nibble)? as u16;
    }

    StandardId::new(value).ok_or(FrameParseError::StandardIdOutOfRange(value))
}

pub fn extended_id_from_hex(hex_nibbles: &[u8; 8]) -> Result<ExtendedId, FrameParseError> {
    let mut value = 0u32;

    for nibble in hex_nibbles.iter() {
        value <<= 4;

        value |= hex_digit_to_u8(*nibble)? as u32;
    }

    ExtendedId::new(value).ok_or(FrameParseError::ExtendedIdOutOfRange(value))
}

pub fn unpack_data_bytes(
    hex_bytes: &[u8],
    expected_length: usize,
) -> Result<Vec<u8, MAX_DECODED_DATA_LENGTH>, FrameParseError> {
    // Make sure data is multiple of 2 (otherwise we can't parse the hex digits)
    if hex_bytes.len() % 2 != 0 {
        return Err(FrameParseError::InvalidEncodedDataLength(
            hex_bytes.len() as u8
        ));
    }

    // Make sure the data length matches the DLC
    if hex_bytes.len() / 2 != expected_length {
        return Err(FrameParseError::MismatchedDataLength(
            expected_length as u8,
            hex_bytes.len() / 2,
        ));
    }

    let mut buf = Vec::new();

    // Iterate over pairs of hex digits
    hex_bytes.chunks(2).try_for_each(|chunk| {
        buf.push(u8_from_hex_nibbles(chunk.try_into().unwrap())?)
            .unwrap();
        Ok(())
    })?;

    Ok(buf)
}
