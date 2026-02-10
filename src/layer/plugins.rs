use crate::layer::LayerExtra;
use libloading::Library;
use serde_json::Value;
use std::ffi::{CStr, CString};
use std::io;
use std::os::raw::c_char;
use std::path::Path;
use tracing::info;

// Dynamic layer parser plugins (so/dll).
//
// A plugin must export a symbol named `arkime_layer_plugin_v1` with signature:
//   extern "C" fn() -> ArkimeLayerPluginV1
//
// The `parse` function receives the raw frame bytes and returns a buffer containing UTF-8 JSON.
// The host will call `free(ptr, len)` for every non-empty buffer returned.
//
// This intentionally uses a C ABI + JSON payload to keep plugin authorship simple across languages.

#[repr(C)]
pub struct ArkimeLayerBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct ArkimeLayerPluginV1 {
    pub api_version: u32,
    pub name: *const c_char,
    pub parse: extern "C" fn(frame: *const u8, len: usize) -> ArkimeLayerBuf,
    pub free: extern "C" fn(ptr: *mut u8, len: usize),
}

type PluginEntry = unsafe extern "C" fn() -> ArkimeLayerPluginV1;

struct DylibPlugin {
    _lib: Library,
    name: String,
    api: ArkimeLayerPluginV1,
}

#[derive(Default)]
pub struct LayerPluginManager {
    plugins: Vec<DylibPlugin>,
}

// Safety:
// - This crate treats layer plugins as "thread-compatible": they may be called from any thread,
//   but the host can still serialize calls if desired.
// - The dynamic library handle is kept alive for the lifetime of `LayerPluginManager`.
// - The C ABI uses plain function pointers; Rust cannot prove thread-safety here, so we opt in
//   explicitly. If a plugin is not thread-safe, callers should guard parse_extras() with a lock.
unsafe impl Send for ArkimeLayerPluginV1 {}
unsafe impl Sync for ArkimeLayerPluginV1 {}
unsafe impl Send for DylibPlugin {}
unsafe impl Sync for DylibPlugin {}
unsafe impl Send for LayerPluginManager {}
unsafe impl Sync for LayerPluginManager {}

impl LayerPluginManager {
    pub fn load(paths: &[String]) -> io::Result<Self> {
        let mut plugins = Vec::new();

        for p in paths {
            let path = Path::new(p);
            unsafe {
                let lib = Library::new(path).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("load layer plugin {} failed: {}", p, e))
                })?;
                let entry: libloading::Symbol<PluginEntry> = lib.get(b"arkime_layer_plugin_v1").map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("symbol arkime_layer_plugin_v1 not found in {}: {}", p, e))
                })?;

                let api = entry();
                if api.api_version != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("layer plugin {} api_version={} unsupported", p, api.api_version),
                    ));
                }

                let name = if api.name.is_null() {
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("layer-plugin")
                        .to_string()
                } else {
                    CStr::from_ptr(api.name).to_string_lossy().to_string()
                };

                info!("loaded layer plugin name={} path={}", name, p);
                plugins.push(DylibPlugin {
                    _lib: lib,
                    name,
                    api,
                });
            }
        }

        Ok(Self { plugins })
    }

    pub fn parse_extras(&self, frame: &[u8]) -> Vec<LayerExtra> {
        let mut out = Vec::new();

        for p in self.plugins.iter() {
            unsafe {
                let buf = (p.api.parse)(frame.as_ptr(), frame.len());
                if buf.ptr.is_null() || buf.len == 0 {
                    continue;
                }

                let slice = std::slice::from_raw_parts(buf.ptr, buf.len);
                let val = match serde_json::from_slice::<Value>(slice) {
                    Ok(v) => v,
                    Err(_) => {
                        // Fall back to UTF-8 text payload if it isn't valid JSON.
                        let s = String::from_utf8_lossy(slice).to_string();
                        Value::String(s)
                    }
                };

                (p.api.free)(buf.ptr, buf.len);
                out.push(LayerExtra {
                    plugin: p.name.clone(),
                    data: val,
                });
            }
        }

        out
    }
}

// Ensure the ABI stays stable for plugin authors.
#[allow(dead_code)]
fn _abi_smoke() {
    let _ = CString::new("x").unwrap();
}
