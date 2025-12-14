//! Build script for QUAC 100 Rust SDK
//!
//! This script configures linking to the native QUAC 100 library.

fn main() {
    // Re-run if these change
    println!("cargo:rerun-if-env-changed=QUAC100_LIB_DIR");
    println!("cargo:rerun-if-env-changed=QUAC100_INCLUDE_DIR");

    // Try to find the library
    let lib_dir = std::env::var("QUAC100_LIB_DIR").ok();
    let include_dir = std::env::var("QUAC100_INCLUDE_DIR").ok();

    // Add library search path
    if let Some(dir) = lib_dir {
        println!("cargo:rustc-link-search=native={}", dir);
    } else {
        // Local stub for testing
        println!("cargo:rustc-link-search=native=D:/quantacore-sdk/bindings/rust/lib");
        // Default search paths
        #[cfg(target_os = "windows")]
        {
            println!("cargo:rustc-link-search=native=C:/Program Files/Dyber/QUAC100/lib");
            println!("cargo:rustc-link-search=native=C:/Dyber/lib");
        }

        #[cfg(target_os = "linux")]
        {
            println!("cargo:rustc-link-search=native=/usr/local/lib");
            println!("cargo:rustc-link-search=native=/usr/lib");
            println!("cargo:rustc-link-search=native=/opt/dyber/lib");
        }

        #[cfg(target_os = "macos")]
        {
            println!("cargo:rustc-link-search=native=/usr/local/lib");
            println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
            println!("cargo:rustc-link-search=native=/opt/dyber/lib");
        }
    }

    // Add include path for bindgen (if used)
    if let Some(dir) = include_dir {
        println!("cargo:include={}", dir);
    }

    // Link to the native library
    #[cfg(target_os = "windows")]
    println!("cargo:rustc-link-lib=dylib=quac100");

    #[cfg(not(target_os = "windows"))]
    println!("cargo:rustc-link-lib=dylib=quac100");

    // Try pkg-config on Unix systems
    #[cfg(unix)]
    {
        if pkg_config::probe_library("quac100").is_ok() {
            println!("cargo:rustc-cfg=has_pkgconfig");
        }
    }
}
