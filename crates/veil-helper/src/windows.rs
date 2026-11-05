//! Windows: the service-based helper comes in stage W3.

use std::path::Path;

use anyhow::{Result, bail};

use crate::{Request, Response};

pub fn call(_req: &Request) -> Result<Response> {
    bail!("TUN mode is not supported on Windows yet")
}

pub fn install(_helper_binary: &Path) -> Result<()> {
    bail!("TUN mode is not supported on Windows yet")
}

pub fn uninstall() -> Result<()> {
    bail!("TUN mode is not supported on Windows yet")
}
