#![no_std]

mod codec;
mod command;
mod event;
mod frame;

// Transmit, Extended, 1FFFFFFF, FD (no brs), DLC = 15, 0x00 * 64
// T E 1FFFFFFF F F 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000

const MAX_ID_SIZE: usize = 8;

const MAX_ENCODED_DATA_LENGTH: usize = 128;
const MAX_DECODED_DATA_LENGTH: usize = MAX_ENCODED_DATA_LENGTH / 2;

pub const MAX_MESSAGE_SIZE: usize = MAX_ENCODED_DATA_LENGTH + MAX_ID_SIZE + 4;
pub const MAX_MESSAGE_DATA_SIZE: usize = MAX_MESSAGE_SIZE - 1;

pub use command::*;
pub use event::*;
pub use frame::*;

pub use embedded_can::{ExtendedId, Id, StandardId};
