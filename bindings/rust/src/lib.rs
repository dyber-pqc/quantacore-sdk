//! # QuantaCore SDK for Rust
//!
//! Rust bindings for the QUAC 100 Post-Quantum Cryptographic Accelerator.
//!
//! ## Features
//!
//! - **ML-KEM (Kyber)**: Post-quantum key encapsulation (512, 768, 1024)
//! - **ML-DSA (Dilithium)**: Post-quantum digital signatures (44, 65, 87)
//! - **QRNG**: Quantum random number generation
//! - **Hardware Hashing**: SHA-2, SHA-3, SHAKE, HMAC, HKDF
//! - **HSM Key Storage**: Secure key management
//!
//! ## Quick Start
//!
//! ```no_run
//! use quantacore::{initialize, cleanup, open_first_device, KemAlgorithm};
//!
//! fn main() -> quantacore::Result<()> {
//!     // Initialize library
//!     initialize()?;
//!
//!     // Open device
//!     let device = open_first_device()?;
//!
//!     // Get KEM subsystem
//!     let kem = device.kem();
//!
//!     // Generate ML-KEM-768 key pair
//!     let keypair = kem.generate_keypair(KemAlgorithm::MlKem768)?;
//!     println!("Public key: {} bytes", keypair.public_key().len());
//!
//!     // Encapsulate
//!     let (ciphertext, shared_secret) = kem.encapsulate(
//!         keypair.public_key(),
//!         KemAlgorithm::MlKem768
//!     )?;
//!
//!     // Decapsulate
//!     let decap_secret = kem.decapsulate(
//!         keypair.secret_key(),
//!         &ciphertext,
//!         KemAlgorithm::MlKem768
//!     )?;
//!
//!     assert_eq!(shared_secret, decap_secret);
//!
//!     // Cleanup
//!     drop(device);
//!     cleanup()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Error Handling
//!
//! All fallible operations return `quantacore::Result<T>`, which is an alias
//! for `std::result::Result<T, QuacError>`.
//!
//! ## Thread Safety
//!
//! The library is thread-safe. Multiple threads can use the same `Device`
//! instance concurrently.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// Modules
mod error;
mod ffi;
mod types;
mod library;
mod device;
mod kem;
mod sign;
mod hash;
mod random;
mod keys;
pub mod utils;

// Re-exports
pub use error::{QuacError, ErrorCode, Result};
pub use types::{
    KemAlgorithm,
    SignAlgorithm,
    HashAlgorithm,
    KeyType,
    KeyUsage,
    InitFlags,
};
pub use library::{LibraryContext, 
    initialize,
    initialize_with_flags,
    cleanup,
    is_initialized,
    get_version,
    get_build_info,
    get_device_count,
    enumerate_devices,
    open_device,
    open_first_device,
};
pub use device::{Device, DeviceInfo, DeviceStatus};
pub use kem::{Kem, KeyPair, EncapsulationResult};
pub use sign::{Sign, SignatureKeyPair};
pub use hash::{Hash, HashContext};
pub use random::{Random, EntropyStatus};
pub use keys::{Keys, KeyInfo};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate prelude for convenient imports
pub mod prelude {
    //! Convenient imports for common use cases.
    //!
    //! ```
    //! use quantacore::prelude::*;
    //! ```

    pub use crate::{
        initialize,
        cleanup,
        open_first_device,
        KemAlgorithm,
        SignAlgorithm,
        HashAlgorithm,
        Result,
        QuacError,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
