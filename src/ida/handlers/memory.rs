//! Memory read/write handlers.

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use crate::ida::types::BytesResult;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_get_bytes(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: u64,
    size: usize,
) -> Result<BytesResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;

    // Limit size to prevent huge reads
    let size = size.min(0x10000); // 64KB max

    let bytes = db.get_bytes(addr, size);
    let hex_string = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(BytesResult {
        address: format!("{:#x}", addr),
        bytes: hex_string,
        length: bytes.len(),
    })
}

pub fn handle_patch_bytes(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: u64,
    bytes: &[u8],
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    db.patch_bytes(addr, bytes)?;
    Ok(json!({
        "address": format!("{:#x}", addr),
        "length": bytes.len(),
    }))
}

pub fn handle_patch_asm(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: u64,
    line: &str,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    let bytes = db
        .assemble_line(addr, line)
        .map_err(|e| ToolError::IdaError(e.to_string()))?;
    db.patch_bytes(addr, &bytes)?;
    let hex = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(json!({
        "address": format!("{:#x}", addr),
        "line": line,
        "length": bytes.len(),
        "bytes": hex,
    }))
}

pub fn handle_read_int(idb: &Option<IDB>, addr: u64, size: usize) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let value = match size {
        1 => db.get_byte(addr) as u64,
        2 => db.get_word(addr) as u64,
        4 => db.get_dword(addr) as u64,
        8 => db.get_qword(addr),
        _ => {
            return Err(ToolError::IdaError(format!(
                "unsupported integer size: {}",
                size
            )))
        }
    };

    Ok(json!({
        "address": format!("{:#x}", addr),
        "size": size,
        "value": value,
        "hex": format!("0x{:x}", value)
    }))
}

/// Parsed integer type descriptor.
struct IntType {
    bits: usize,
    signed: bool,
    big_endian: bool,
}

impl IntType {
    fn byte_size(&self) -> usize {
        self.bits / 8
    }

    fn normalized(&self) -> String {
        let sign = if self.signed { "i" } else { "u" };
        let endian = if self.bits > 8 {
            if self.big_endian { "be" } else { "le" }
        } else {
            ""
        };
        format!("{sign}{}{endian}", self.bits)
    }
}

/// Parse a type string like "u16le", "i32be", "u8", etc.
fn parse_int_type(ty: &str) -> Result<IntType, ToolError> {
    let ty = ty.trim().to_lowercase();
    if ty.is_empty() {
        return Err(ToolError::InvalidParams("empty type string".to_string()));
    }

    let signed = match ty.as_bytes()[0] {
        b'i' => true,
        b'u' => false,
        _ => return Err(ToolError::InvalidParams(format!(
            "type must start with 'i' or 'u', got: {ty}"
        ))),
    };

    let rest = &ty[1..];

    // Try to extract bits and optional endianness suffix
    let (bits_str, endian_str) = if let Some(stripped) = rest.strip_suffix("le") {
        (stripped, "le")
    } else if let Some(stripped) = rest.strip_suffix("be") {
        (stripped, "be")
    } else {
        (rest, "")
    };

    let bits: usize = bits_str.parse().map_err(|_| {
        ToolError::InvalidParams(format!("invalid bit width in type: {ty}"))
    })?;

    if !matches!(bits, 8 | 16 | 32 | 64) {
        return Err(ToolError::InvalidParams(format!(
            "unsupported bit width {bits}, must be 8/16/32/64"
        )));
    }

    let big_endian = endian_str == "be";

    Ok(IntType { bits, signed, big_endian })
}

/// Parse an integer value from a string (supports 0x, negative, decimal).
fn parse_int_value(s: &str) -> Result<i128, ToolError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ToolError::InvalidParams("empty value string".to_string()));
    }

    let negative = s.starts_with('-');
    let abs_str = if negative { &s[1..] } else { s };
    let abs_str = abs_str.trim();

    let abs_val: u128 = if abs_str.starts_with("0x") || abs_str.starts_with("0X") {
        u128::from_str_radix(&abs_str[2..], 16)
            .map_err(|_| ToolError::InvalidParams(format!("invalid hex value: {s}")))?
    } else if abs_str.starts_with("0b") || abs_str.starts_with("0B") {
        u128::from_str_radix(&abs_str[2..], 2)
            .map_err(|_| ToolError::InvalidParams(format!("invalid binary value: {s}")))?
    } else {
        abs_str.parse::<u128>()
            .map_err(|_| ToolError::InvalidParams(format!("invalid value: {s}")))?
    };

    if negative {
        Ok(-(abs_val as i128))
    } else {
        Ok(abs_val as i128)
    }
}

/// Read a typed integer at an address.
pub fn handle_get_int(idb: &Option<IDB>, addr: u64, ty: &str) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let parsed = parse_int_type(ty)?;
    let size = parsed.byte_size();
    let bytes = db.get_bytes(addr, size);
    if bytes.len() < size {
        return Err(ToolError::IdaError(format!(
            "could not read {size} bytes at {addr:#x}"
        )));
    }

    let raw_bytes: &[u8] = &bytes[..size];

    // Convert to unsigned u64 value respecting endianness
    let unsigned_val: u64 = match size {
        1 => raw_bytes[0] as u64,
        2 => {
            let arr: [u8; 2] = raw_bytes.try_into().unwrap();
            if parsed.big_endian { u16::from_be_bytes(arr) as u64 } else { u16::from_le_bytes(arr) as u64 }
        }
        4 => {
            let arr: [u8; 4] = raw_bytes.try_into().unwrap();
            if parsed.big_endian { u32::from_be_bytes(arr) as u64 } else { u32::from_le_bytes(arr) as u64 }
        }
        8 => {
            let arr: [u8; 8] = raw_bytes.try_into().unwrap();
            if parsed.big_endian { u64::from_be_bytes(arr) } else { u64::from_le_bytes(arr) }
        }
        _ => unreachable!(),
    };

    // Produce signed interpretation if requested
    let value: Value = if parsed.signed {
        let signed_val: i64 = match size {
            1 => unsigned_val as u8 as i8 as i64,
            2 => unsigned_val as u16 as i16 as i64,
            4 => unsigned_val as u32 as i32 as i64,
            8 => unsigned_val as i64,
            _ => unreachable!(),
        };
        json!(signed_val)
    } else {
        json!(unsigned_val)
    };

    Ok(json!({
        "addr": format!("{:#x}", addr),
        "ty": parsed.normalized(),
        "value": value,
        "hex": format!("{:#x}", unsigned_val),
    }))
}

/// Write a typed integer at an address.
pub fn handle_put_int(idb: &Option<IDB>, addr: u64, ty: &str, value_str: &str) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let parsed = parse_int_type(ty)?;
    let size = parsed.byte_size();
    let value = parse_int_value(value_str)?;

    // Convert to bytes
    let bytes: Vec<u8> = match size {
        1 => {
            let v = value as u8;
            vec![v]
        }
        2 => {
            let v = value as u16;
            if parsed.big_endian { v.to_be_bytes().to_vec() } else { v.to_le_bytes().to_vec() }
        }
        4 => {
            let v = value as u32;
            if parsed.big_endian { v.to_be_bytes().to_vec() } else { v.to_le_bytes().to_vec() }
        }
        8 => {
            let v = value as u64;
            if parsed.big_endian { v.to_be_bytes().to_vec() } else { v.to_le_bytes().to_vec() }
        }
        _ => unreachable!(),
    };

    db.patch_bytes(addr, &bytes)?;

    Ok(json!({
        "addr": format!("{:#x}", addr),
        "ty": parsed.normalized(),
        "value": value_str,
        "ok": true,
    }))
}
