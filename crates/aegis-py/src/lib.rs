use aegis_core::{sanitize_bytes, sanitize_text, scan_bytes};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

#[pyfunction]
fn scan_bytes_native<'py>(
    py: Python<'py>,
    payload: &[u8],
    source: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let report = py.allow_threads(|| scan_bytes(payload, source));

    let dict = PyDict::new(py);
    dict.set_item("source", report.source)?;
    dict.set_item("sha256", report.sha256)?;
    dict.set_item("byte_length", report.byte_length)?;
    dict.set_item("risk_score", report.risk_score)?;
    dict.set_item("verdict", report.verdict)?;
    dict.set_item("requires_human_review", report.requires_human_review)?;

    let py_findings = PyList::empty(py);
    for f in report.findings {
        let fd = PyDict::new(py);
        fd.set_item("rule_id", f.rule_id)?;
        fd.set_item("category", f.category)?;
        fd.set_item("severity", f.severity.as_str())?;
        fd.set_item("line", f.line)?;
        fd.set_item("offset", f.offset)?;
        fd.set_item("description", f.description)?;
        fd.set_item("snippet", f.snippet)?;
        py_findings.append(fd)?;
    }
    dict.set_item("findings", py_findings)?;

    Ok(dict)
}

#[pyfunction]
fn sanitize_text_native(text: &str) -> String {
    sanitize_text(text)
}

#[pyfunction]
fn sanitize_bytes_native(py: Python<'_>, payload: &[u8]) -> String {
    py.allow_threads(|| sanitize_bytes(payload))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_bytes_native, m)?)?;
    m.add_function(wrap_pyfunction!(sanitize_text_native, m)?)?;
    m.add_function(wrap_pyfunction!(sanitize_bytes_native, m)?)?;
    Ok(())
}
