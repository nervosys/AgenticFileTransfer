//! Plugin system for custom protocol handlers.
//!
//! Plugins are shared libraries (.dll on Windows, .so on Linux, .dylib on macOS)
//! that export a `create_plugin` function returning a `Box<dyn Plugin>`.
//!
//! Plugins are loaded from `~/.aft/plugins/` and can register custom protocol
//! schemes that integrate seamlessly with the existing `resolve_protocol()` system.
//!
//! ## Creating a Plugin
//!
//! ```rust,ignore
//! use aft::plugins::{Plugin, PluginMetadata};
//! use aft::protocols::ProtocolHandler;
//!
//! struct MyPlugin;
//!
//! impl Plugin for MyPlugin {
//!     fn metadata(&self) -> PluginMetadata {
//!         PluginMetadata {
//!             name: "my-protocol".into(),
//!             version: "0.1.0".into(),
//!             scheme: "myproto".into(),
//!             description: "My custom protocol handler".into(),
//!         }
//!     }
//!
//!     fn create_handler(&self) -> Box<dyn ProtocolHandler> {
//!         Box::new(MyHandler)
//!     }
//! }
//!
//! #[no_mangle]
//! pub extern "C" fn create_plugin() -> *mut dyn Plugin {
//!     Box::into_raw(Box::new(MyPlugin))
//! }
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{AftError, AftResult};
use crate::protocols::ProtocolHandler;

// ── Plugin trait ────────────────────────────────────────────────────────────

/// Metadata describing a plugin.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub scheme: String,
    pub description: String,
}

/// Trait that all plugins must implement.
pub trait Plugin: Send + Sync {
    /// Return metadata about this plugin.
    fn metadata(&self) -> PluginMetadata;

    /// Create a new protocol handler instance.
    fn create_handler(&self) -> Box<dyn ProtocolHandler>;
}

// ── Plugin Registry ─────────────────────────────────────────────────────────

/// Manages loaded plugins and their protocol handlers.
pub struct PluginRegistry {
    plugins: HashMap<String, LoadedPlugin>,
}

struct LoadedPlugin {
    metadata: PluginMetadata,
    plugin: Box<dyn Plugin>,
    #[allow(dead_code)]
    library: Option<Arc<libloading::Library>>,
}

impl PluginRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Load all plugins from the default plugins directory (~/.aft/plugins/).
    pub fn load_from_default_dir(&mut self) -> AftResult<Vec<PluginMetadata>> {
        let plugins_dir = default_plugins_dir()?;
        if !plugins_dir.exists() {
            return Ok(Vec::new());
        }
        self.load_from_dir(&plugins_dir)
    }

    /// Load all plugins from a directory.
    pub fn load_from_dir(&mut self, dir: &Path) -> AftResult<Vec<PluginMetadata>> {
        let mut loaded = Vec::new();

        if !dir.is_dir() {
            return Ok(loaded);
        }

        let ext = plugin_extension();
        let entries = std::fs::read_dir(dir)
            .map_err(|e| AftError::Other(format!("Cannot read plugins dir {:?}: {}", dir, e)))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some(ext) {
                match self.load_plugin(&path) {
                    Ok(meta) => loaded.push(meta),
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to load plugin {:?}: {}",
                            path.file_name().unwrap_or_default(),
                            e
                        );
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Load a single plugin from a shared library path.
    pub fn load_plugin(&mut self, path: &Path) -> AftResult<PluginMetadata> {
        // Validate the path exists and is a file
        if !path.is_file() {
            return Err(AftError::FileNotFound(format!(
                "Plugin file not found: {:?}",
                path
            )));
        }

        // Safety: Loading shared libraries is inherently unsafe.
        // We trust that plugins from ~/.aft/plugins/ are user-installed.
        let library = unsafe {
            libloading::Library::new(path)
                .map_err(|e| AftError::Other(format!("Cannot load plugin {:?}: {}", path, e)))?
        };

        let plugin: Box<dyn Plugin> = unsafe {
            let constructor: libloading::Symbol<unsafe extern "C" fn() -> *mut dyn Plugin> =
                library.get(b"create_plugin").map_err(|e| {
                    AftError::Other(format!(
                        "Plugin {:?} missing create_plugin symbol: {}",
                        path, e
                    ))
                })?;

            Box::from_raw(constructor())
        };

        let metadata = plugin.metadata();
        let scheme = metadata.scheme.clone();

        if self.plugins.contains_key(&scheme) {
            return Err(AftError::Other(format!(
                "Plugin scheme '{}' already registered",
                scheme
            )));
        }

        self.plugins.insert(
            scheme,
            LoadedPlugin {
                metadata: metadata.clone(),
                plugin,
                library: Some(Arc::new(library)),
            },
        );

        Ok(metadata)
    }

    /// Unload a plugin by scheme.
    pub fn unload(&mut self, scheme: &str) -> AftResult<()> {
        if self.plugins.remove(scheme).is_none() {
            return Err(AftError::Other(format!(
                "No plugin registered for scheme '{}'",
                scheme
            )));
        }
        Ok(())
    }

    /// Check if a scheme is handled by a plugin.
    #[allow(dead_code)]
    pub fn has_scheme(&self, scheme: &str) -> bool {
        self.plugins.contains_key(scheme)
    }

    /// Create a protocol handler for a scheme, if a plugin provides it.
    pub fn create_handler(&self, scheme: &str) -> Option<Box<dyn ProtocolHandler>> {
        self.plugins
            .get(scheme)
            .map(|lp| lp.plugin.create_handler())
    }

    /// List all loaded plugins.
    pub fn list(&self) -> Vec<&PluginMetadata> {
        self.plugins.values().map(|lp| &lp.metadata).collect()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn default_plugins_dir() -> AftResult<PathBuf> {
    let aft_dir = crate::config::ensure_aft_dir()?;
    Ok(aft_dir.join("plugins"))
}

fn plugin_extension() -> &'static str {
    if cfg!(target_os = "windows") {
        "dll"
    } else if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    }
}

// ── Global registry ─────────────────────────────────────────────────────────

use std::sync::Mutex;
use std::sync::OnceLock;

static PLUGIN_REGISTRY: OnceLock<Mutex<PluginRegistry>> = OnceLock::new();

/// Initialize the global plugin registry (called once at startup).
pub fn init_registry() -> AftResult<()> {
    let mut registry = PluginRegistry::new();
    let _ = registry.load_from_default_dir();
    PLUGIN_REGISTRY
        .set(Mutex::new(registry))
        .map_err(|_| AftError::Other("Plugin registry already initialized".into()))?;
    Ok(())
}

/// Get a reference to the global plugin registry.
pub fn global_registry() -> &'static Mutex<PluginRegistry> {
    PLUGIN_REGISTRY.get_or_init(|| Mutex::new(PluginRegistry::new()))
}
