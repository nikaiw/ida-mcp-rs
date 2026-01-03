//! Cross-reference handlers.

use crate::error::ToolError;
use crate::ida::types::XRefInfo;
use idalib::xref::XRefQuery;
use idalib::IDB;
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn handle_xrefs_to(idb: &Option<IDB>, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut xrefs = Vec::new();
    let mut current = db.first_xref_to(addr, XRefQuery::ALL);

    while let Some(xref) = current {
        xrefs.push(XRefInfo {
            from: format!("{:#x}", xref.from()),
            to: format!("{:#x}", xref.to()),
            r#type: format!("{:?}", xref.type_()),
            is_code: xref.is_code(),
        });
        current = xref.next_to();
    }

    Ok(xrefs)
}

pub fn handle_xrefs_from(idb: &Option<IDB>, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut xrefs = Vec::new();
    let mut current = db.first_xref_from(addr, XRefQuery::ALL);

    while let Some(xref) = current {
        xrefs.push(XRefInfo {
            from: format!("{:#x}", xref.from()),
            to: format!("{:#x}", xref.to()),
            r#type: format!("{:?}", xref.type_()),
            is_code: xref.is_code(),
        });
        current = xref.next_from();
    }

    Ok(xrefs)
}

pub fn handle_xref_matrix(idb: &Option<IDB>, addrs: &[u64]) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let mut xref_map: std::collections::HashMap<u64, HashSet<u64>> =
        std::collections::HashMap::new();

    for &addr in addrs {
        let mut set = HashSet::new();
        let mut current = db.first_xref_from(addr, XRefQuery::ALL);
        while let Some(xref) = current {
            set.insert(xref.to());
            current = xref.next_from();
        }
        xref_map.insert(addr, set);
    }

    let matrix: Vec<Vec<bool>> = addrs
        .iter()
        .map(|from| {
            addrs
                .iter()
                .map(|to| xref_map.get(from).map(|s| s.contains(to)).unwrap_or(false))
                .collect()
        })
        .collect();

    Ok(json!({
        "addrs": addrs.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>(),
        "matrix": matrix
    }))
}
