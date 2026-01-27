//! Python scripting support via extlang API.

use crate::error::ToolError;
use crate::ida::types::PyEvalResult;
use idalib::IDB;
use std::ffi::CString;

/// Check if Python extlang is available.
pub fn handle_has_python() -> bool {
    unsafe { idalib::ffi::py_eval::idalib_has_python_extlang() }
}

/// Execute Python code in IDA context.
///
/// This uses IDA's extlang API to execute Python code through IDAPython.
/// The code can be either an expression (returns a value) or statements.
pub fn handle_py_eval(
    _idb: &Option<IDB>,
    code: &str,
    current_ea: Option<u64>,
) -> Result<PyEvalResult, ToolError> {
    // Check if a database is open (optional, but useful context)
    // let _db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let code_cstr = CString::new(code).map_err(|e| ToolError::InvalidParams(e.to_string()))?;

    // Try to evaluate as an expression first (returns value)
    // If that fails, try as a snippet (statements)
    let mut result = idalib::ffi::py_eval::py_eval_result::default();

    // Try expression evaluation first if we have a current EA
    let ea = current_ea.unwrap_or(0);
    let ok = unsafe {
        idalib::ffi::py_eval::idalib_py_eval_expr(code_cstr.as_ptr(), ea, &mut result)
    };

    if ok && result.success {
        return Ok(PyEvalResult {
            success: true,
            result: result.result,
            error: None,
        });
    }

    // If expression eval failed, try as a snippet (statements)
    let mut result = idalib::ffi::py_eval::py_eval_result::default();
    let ok = unsafe {
        idalib::ffi::py_eval::idalib_py_eval_snippet(code_cstr.as_ptr(), &mut result)
    };

    if ok && result.success {
        Ok(PyEvalResult {
            success: true,
            result: result.result,
            error: None,
        })
    } else {
        // Return the error
        Ok(PyEvalResult {
            success: false,
            result: String::new(),
            error: Some(result.error),
        })
    }
}
