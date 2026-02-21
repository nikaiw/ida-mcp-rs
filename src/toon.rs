//! TOON (Token-Oriented Object Notation) encoder for tabular data.
//!
//! TOON encodes arrays of homogeneous structs as header + rows instead of
//! repeating JSON keys per object. This achieves 30-40% token savings for LLM
//! responses containing tabular data (function lists, xrefs, strings, etc.).
//!
//! Format:
//! ```text
//! [TOON]
//! {address,name,size}:
//! 0x1000,main,42
//! 0x2000,foo,10
//! ```
//!
//! For wrapper types with scalar metadata:
//! ```text
//! total=500,next_offset=100
//! [TOON]
//! {address,name,size}:
//! 0x1000,main,42
//! ```

use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

/// Attempt to encode a serializable value in TOON format.
/// Returns `Some(encoded)` if the value contains tabular data suitable
/// for TOON encoding, `None` otherwise.
pub fn try_encode<T: Serialize>(value: &T) -> Option<String> {
    let json = serde_json::to_value(value).ok()?;
    match &json {
        // Direct array: Vec<XRefInfo>, Vec<FunctionInfo>, etc.
        Value::Array(arr) => encode_array(arr),
        // Wrapper object: FunctionListResult { functions: [...], total, ... }
        Value::Object(map) => encode_object_with_arrays(map),
        // Not tabular
        _ => None,
    }
}

/// Encode a JSON array as TOON if all elements are homogeneous objects.
fn encode_array(arr: &[Value]) -> Option<String> {
    if arr.is_empty() {
        return None;
    }

    // All items must be objects
    if !arr.iter().all(|v| v.is_object()) {
        return None;
    }

    // Collect union of all keys (preserving first-appearance order)
    let mut keys: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for item in arr {
        if let Some(obj) = item.as_object() {
            for key in obj.keys() {
                if seen.insert(key.clone()) {
                    keys.push(key.clone());
                }
            }
        }
    }

    if keys.is_empty() {
        return None;
    }

    let mut out = String::with_capacity(arr.len() * 64);
    out.push_str("[TOON]\n");

    // Header row
    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(key);
    }
    out.push_str("}:\n");

    // Data rows
    for item in arr {
        let obj = item.as_object().unwrap();
        for (i, key) in keys.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            if let Some(val) = obj.get(key) {
                encode_value(val, &mut out);
            }
            // Missing key = empty cell
        }
        out.push('\n');
    }

    Some(out)
}

/// Encode an object that contains array fields + scalar metadata.
/// Example: { "functions": [...], "total": 500, "next_offset": 100 }
fn encode_object_with_arrays(map: &serde_json::Map<String, Value>) -> Option<String> {
    // Find the first array field with 2+ homogeneous objects
    let mut array_field: Option<(&str, &Vec<Value>)> = None;
    let mut scalar_fields: Vec<(&str, &Value)> = Vec::new();

    for (key, value) in map {
        match value {
            Value::Array(arr) if !arr.is_empty() && arr[0].is_object() => {
                if array_field.is_none() {
                    array_field = Some((key.as_str(), arr));
                }
            }
            _ => {
                // Skip null optional fields
                if !value.is_null() {
                    scalar_fields.push((key.as_str(), value));
                }
            }
        }
    }

    let (_arr_name, arr) = array_field?;
    let toon_body = encode_array(arr)?;

    // If no scalar fields, just return the TOON body
    if scalar_fields.is_empty() {
        return Some(toon_body);
    }

    // Prepend scalar metadata
    let mut out = String::with_capacity(toon_body.len() + 64);
    for (i, (key, value)) in scalar_fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(key);
        out.push('=');
        encode_value(value, &mut out);
    }
    out.push('\n');
    out.push_str(&toon_body);
    Some(out)
}

/// Encode a single JSON value as a TOON cell.
fn encode_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => { /* empty cell */ }
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            if needs_quoting(s) {
                out.push('"');
                for ch in s.chars() {
                    if ch == '"' {
                        out.push_str("\"\"");
                    } else {
                        out.push(ch);
                    }
                }
                out.push('"');
            } else {
                out.push_str(s);
            }
        }
        Value::Array(arr) => {
            // Sub-array: join with | delimiter, quoting items that contain delimiters
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push('|');
                }
                match item {
                    Value::String(s) => {
                        if s.contains('|') || s.contains(',') || s.contains('\n') {
                            out.push('"');
                            for ch in s.chars() {
                                if ch == '"' {
                                    out.push_str("\"\"");
                                } else {
                                    out.push(ch);
                                }
                            }
                            out.push('"');
                        } else {
                            out.push_str(s);
                        }
                    }
                    Value::Number(n) => out.push_str(&n.to_string()),
                    Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
                    other => out.push_str(&other.to_string()),
                }
            }
        }
        Value::Object(_) => {
            // Nested object: quote as JSON to avoid comma conflicts
            let json = value.to_string();
            out.push('"');
            for ch in json.chars() {
                if ch == '"' {
                    out.push_str("\"\"");
                } else {
                    out.push(ch);
                }
            }
            out.push('"');
        }
    }
}

/// Check if a string needs quoting (contains comma, newline, or double quote).
fn needs_quoting(s: &str) -> bool {
    s.contains(',') || s.contains('\n') || s.contains('\r') || s.contains('"')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct FuncInfo {
        address: String,
        name: String,
        size: usize,
    }

    #[test]
    fn test_basic_toon_encoding() {
        let items = vec![
            FuncInfo {
                address: "0x1000".into(),
                name: "main".into(),
                size: 42,
            },
            FuncInfo {
                address: "0x2000".into(),
                name: "foo".into(),
                size: 10,
            },
        ];
        let result = try_encode(&items).unwrap();
        assert!(result.starts_with("[TOON]\n"));
        assert!(result.contains("{address,name,size}:"));
        assert!(result.contains("0x1000,main,42"));
        assert!(result.contains("0x2000,foo,10"));
    }

    #[test]
    fn test_wrapper_type() {
        #[derive(Serialize)]
        struct FuncList {
            functions: Vec<FuncInfo>,
            total: usize,
        }
        let list = FuncList {
            functions: vec![
                FuncInfo {
                    address: "0x1000".into(),
                    name: "main".into(),
                    size: 42,
                },
                FuncInfo {
                    address: "0x2000".into(),
                    name: "foo".into(),
                    size: 10,
                },
            ],
            total: 2,
        };
        let result = try_encode(&list).unwrap();
        assert!(result.contains("total=2"));
        assert!(result.contains("{address,name,size}:"));
    }

    #[test]
    fn test_wrapper_with_optional_field() {
        #[derive(Serialize)]
        struct FuncList {
            functions: Vec<FuncInfo>,
            total: usize,
            #[serde(skip_serializing_if = "Option::is_none")]
            next_offset: Option<usize>,
        }
        let list = FuncList {
            functions: vec![
                FuncInfo {
                    address: "0x1000".into(),
                    name: "main".into(),
                    size: 42,
                },
                FuncInfo {
                    address: "0x2000".into(),
                    name: "foo".into(),
                    size: 10,
                },
            ],
            total: 100,
            next_offset: Some(2),
        };
        let result = try_encode(&list).unwrap();
        assert!(result.contains("total=100"));
        assert!(result.contains("next_offset=2"));
    }

    #[test]
    fn test_string_with_commas() {
        #[derive(Serialize)]
        struct Str {
            address: String,
            content: String,
            length: usize,
        }
        let items = vec![
            Str {
                address: "0x100".into(),
                content: "hello, world".into(),
                length: 12,
            },
            Str {
                address: "0x200".into(),
                content: "foo".into(),
                length: 3,
            },
        ];
        let result = try_encode(&items).unwrap();
        assert!(result.contains("\"hello, world\""));
    }

    #[test]
    fn test_single_item_encodes() {
        let items = vec![FuncInfo {
            address: "0x1000".into(),
            name: "main".into(),
            size: 42,
        }];
        let result = try_encode(&items).unwrap();
        assert!(result.starts_with("[TOON]\n"));
        assert!(result.contains("{address,name,size}:"));
        assert!(result.contains("0x1000,main,42"));
    }

    #[test]
    fn test_single_object_returns_none() {
        let obj = FuncInfo {
            address: "0x1000".into(),
            name: "main".into(),
            size: 42,
        };
        assert!(try_encode(&obj).is_none());
    }

    #[test]
    fn test_nested_array_fields() {
        #[derive(Serialize)]
        struct BB {
            start: String,
            end: String,
            successors: Vec<String>,
        }
        let items = vec![
            BB {
                start: "0x1000".into(),
                end: "0x1010".into(),
                successors: vec!["0x1010".into(), "0x2000".into()],
            },
            BB {
                start: "0x1010".into(),
                end: "0x1020".into(),
                successors: vec!["0x1020".into()],
            },
        ];
        let result = try_encode(&items).unwrap();
        assert!(result.contains("0x1010|0x2000"));
    }

    #[test]
    fn test_boolean_fields() {
        #[derive(Serialize)]
        struct XRef {
            from: String,
            to: String,
            is_code: bool,
        }
        let items = vec![
            XRef {
                from: "0x1000".into(),
                to: "0x2000".into(),
                is_code: true,
            },
            XRef {
                from: "0x3000".into(),
                to: "0x4000".into(),
                is_code: false,
            },
        ];
        let result = try_encode(&items).unwrap();
        // Keys are alphabetically sorted by serde_json::Map (BTreeMap):
        // from, is_code, to
        assert!(result.contains("{from,is_code,to}:"));
        assert!(result.contains("0x1000,true,0x2000"));
        assert!(result.contains("0x3000,false,0x4000"));
    }

    #[test]
    fn test_optional_fields_union_of_keys() {
        #[derive(Serialize)]
        struct Global {
            address: String,
            name: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            is_weak: Option<bool>,
        }
        let items = vec![
            Global {
                address: "0x1000".into(),
                name: "foo".into(),
                is_weak: Some(true),
            },
            Global {
                address: "0x2000".into(),
                name: "bar".into(),
                is_weak: None,
            },
        ];
        let result = try_encode(&items).unwrap();
        // Keys are alphabetically sorted: address, is_weak, name
        assert!(result.contains("{address,is_weak,name}:"));
        assert!(result.contains("0x1000,true,foo"));
        // bar should have address, empty for is_weak, then name
        assert!(result.contains("0x2000,,bar"));
    }

    #[test]
    fn test_subarray_with_pipe_delimiter() {
        #[derive(Serialize)]
        struct Item {
            name: String,
            tags: Vec<String>,
        }
        let items = vec![Item {
            name: "test".into(),
            tags: vec!["a|b".into(), "c".into()],
        }];
        let result = try_encode(&items).unwrap();
        // Pipe in sub-array item should be quoted
        assert!(result.contains("\"a|b\"|c"));
    }

    #[test]
    fn test_nested_object_quoted() {
        // Nested objects should be quoted to avoid comma corruption
        let json: Value = serde_json::json!([
            {"addr": "0x1000", "meta": {"a": 1, "b": 2}}
        ]);
        let arr = json.as_array().unwrap();
        let result = encode_array(arr).unwrap();
        // The nested object should be wrapped in escaped quotes:
        // 0x1000,"{""a"":1,""b"":2}"
        // Internal commas are inside quotes, so they're not cell delimiters
        assert!(result.contains("\"{\"\"a\"\":1,\"\"b\"\":2}\""));
    }

    #[test]
    fn test_empty_array_returns_none() {
        let items: Vec<FuncInfo> = vec![];
        assert!(try_encode(&items).is_none());
    }

    #[test]
    fn test_string_with_quotes() {
        #[derive(Serialize)]
        struct Str {
            address: String,
            content: String,
        }
        let items = vec![
            Str {
                address: "0x100".into(),
                content: r#"say "hello""#.into(),
            },
            Str {
                address: "0x200".into(),
                content: "normal".into(),
            },
        ];
        let result = try_encode(&items).unwrap();
        // Quotes should be doubled inside quoted value
        assert!(result.contains("\"say \"\"hello\"\"\""));
    }
}
