//! SSH-Datentypen nach RFC 4251 §5: byte, boolean, uint32, uint64, string,
//! mpint und name-list.

mod reader;
mod writer;

pub use reader::Reader;
pub use writer::{MAX_FIELD_LEN, Writer, check_field};
