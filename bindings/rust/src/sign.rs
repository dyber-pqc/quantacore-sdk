//! Digital signature operations.
//!
//! This module provides post-quantum digital signatures using ML-DSA (Dilithium).

use crate::device::Device;
use crate::error::{check_error, QuacError, Result};
use crate::ffi;
use crate::types::SignAlgorithm;

use zeroize::ZeroizeOnDrop;

/// Signature key pair.
///
/// Contains the public and secret keys for digital signatures.
/// The secret key is automatically zeroed when dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SignatureKeyPair {
    /// Public key bytes
    #[zeroize(skip)]
    public_key: Vec<u8>,
    /// Secret key bytes (zeroized on drop)
    secret_key: Vec<u8>,
    /// Algorithm used
    #[zeroize(skip)]
    algorithm: SignAlgorithm,
}

impl SignatureKeyPair {
    /// Create a new signature key pair.
    fn new(public_key: Vec<u8>, secret_key: Vec<u8>, algorithm: SignAlgorithm) -> Self {
        Self {
            public_key,
            secret_key,
            algorithm,
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the secret key.
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    /// Get the algorithm.
    pub fn algorithm(&self) -> SignAlgorithm {
        self.algorithm
    }

    /// Consume the key pair and return the raw bytes.
    pub fn into_bytes(mut self) -> (Vec<u8>, Vec<u8>) {
        let pk = std::mem::take(&mut self.public_key);
        let sk = std::mem::take(&mut self.secret_key);
        std::mem::forget(self);
        (pk, sk)
    }
}

impl std::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("algorithm", &self.algorithm)
            .field("public_key_len", &self.public_key.len())
            .field("secret_key_len", &self.secret_key.len())
            .finish()
    }
}

/// Signature subsystem.
///
/// Provides access to post-quantum digital signature operations
/// using ML-DSA (formerly Dilithium).
///
/// # Example
///
/// ```no_run
/// use quantacore::{initialize, open_first_device, SignAlgorithm};
///
/// initialize().unwrap();
/// let device = open_first_device().unwrap();
/// let sign = device.sign();
///
/// // Generate key pair
/// let keypair = sign.generate_keypair(SignAlgorithm::MlDsa65).unwrap();
///
/// // Sign a message
/// let message = b"Hello, quantum world!";
/// let signature = sign.sign(keypair.secret_key(), message, SignAlgorithm::MlDsa65).unwrap();
///
/// // Verify the signature
/// let valid = sign.verify(keypair.public_key(), message, &signature, SignAlgorithm::MlDsa65).unwrap();
/// assert!(valid);
/// ```
#[derive(Clone)]
pub struct Sign {
    device: Device,
}

impl Sign {
    /// Create a new signature subsystem handle.
    pub(crate) fn new(device: Device) -> Self {
        Self { device }
    }

    /// Generate a signature key pair.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signature algorithm to use
    ///
    /// # Returns
    ///
    /// A `SignatureKeyPair` containing the public and secret keys.
    pub fn generate_keypair(&self, algorithm: SignAlgorithm) -> Result<SignatureKeyPair> {
        let pk_size = algorithm.public_key_size();
        let sk_size = algorithm.secret_key_size();

        let mut public_key = vec![0u8; pk_size];
        let mut secret_key = vec![0u8; sk_size];
        let mut pk_len = pk_size;
        let mut sk_len = sk_size;

        let result = unsafe {
            ffi::quac_sign_keygen(
                self.device.handle(),
                algorithm.to_raw(),
                public_key.as_mut_ptr(),
                &mut pk_len,
                secret_key.as_mut_ptr(),
                &mut sk_len,
            )
        };

        check_error(result)?;

        public_key.truncate(pk_len);
        secret_key.truncate(sk_len);

        Ok(SignatureKeyPair::new(public_key, secret_key, algorithm))
    }

    /// Generate ML-DSA-44 key pair.
    pub fn generate_keypair_44(&self) -> Result<SignatureKeyPair> {
        self.generate_keypair(SignAlgorithm::MlDsa44)
    }

    /// Generate ML-DSA-65 key pair.
    pub fn generate_keypair_65(&self) -> Result<SignatureKeyPair> {
        self.generate_keypair(SignAlgorithm::MlDsa65)
    }

    /// Generate ML-DSA-87 key pair.
    pub fn generate_keypair_87(&self) -> Result<SignatureKeyPair> {
        self.generate_keypair(SignAlgorithm::MlDsa87)
    }

    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The signer's secret key
    /// * `message` - The message to sign
    /// * `algorithm` - The signature algorithm to use
    ///
    /// # Returns
    ///
    /// The digital signature.
    pub fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>> {
        let sig_size = algorithm.signature_size();
        let mut signature = vec![0u8; sig_size];
        let mut sig_len = sig_size;

        let result = unsafe {
            ffi::quac_sign(
                self.device.handle(),
                algorithm.to_raw(),
                secret_key.as_ptr(),
                secret_key.len(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                &mut sig_len,
            )
        };

        check_error(result)?;
        signature.truncate(sig_len);

        Ok(signature)
    }

    /// Sign using ML-DSA-44.
    pub fn sign_44(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        self.sign(secret_key, message, SignAlgorithm::MlDsa44)
    }

    /// Sign using ML-DSA-65.
    pub fn sign_65(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        self.sign(secret_key, message, SignAlgorithm::MlDsa65)
    }

    /// Sign using ML-DSA-87.
    pub fn sign_87(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        self.sign(secret_key, message, SignAlgorithm::MlDsa87)
    }

    /// Sign a string message.
    pub fn sign_str(
        &self,
        secret_key: &[u8],
        message: &str,
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>> {
        self.sign(secret_key, message.as_bytes(), algorithm)
    }

    /// Verify a signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's public key
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    /// * `algorithm` - The signature algorithm to use
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool> {
        let result = unsafe {
            ffi::quac_verify(
                self.device.handle(),
                algorithm.to_raw(),
                public_key.as_ptr(),
                public_key.len(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            )
        };

        match result {
            0 => Ok(true),
            -13 => Ok(false), // VERIFICATION_FAILED
            _ => {
                check_error(result)?;
                Ok(false)
            }
        }
    }

    /// Verify using ML-DSA-44.
    pub fn verify_44(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify(public_key, message, signature, SignAlgorithm::MlDsa44)
    }

    /// Verify using ML-DSA-65.
    pub fn verify_65(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify(public_key, message, signature, SignAlgorithm::MlDsa65)
    }

    /// Verify using ML-DSA-87.
    pub fn verify_87(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify(public_key, message, signature, SignAlgorithm::MlDsa87)
    }

    /// Verify a string message.
    pub fn verify_str(
        &self,
        public_key: &[u8],
        message: &str,
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool> {
        self.verify(public_key, message.as_bytes(), signature, algorithm)
    }

    /// Verify a signature, returning an error if invalid.
    ///
    /// Unlike `verify()` which returns a boolean, this method returns
    /// an error if verification fails, making it suitable for use with `?`.
    pub fn verify_or_error(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<()> {
        if self.verify(public_key, message, signature, algorithm)? {
            Ok(())
        } else {
            Err(QuacError::VerificationFailed)
        }
    }
}

impl std::fmt::Debug for Sign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sign").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_debug_hides_secret() {
        let kp = SignatureKeyPair::new(
            vec![1, 2, 3],
            vec![4, 5, 6],
            SignAlgorithm::MlDsa65,
        );
        let debug = format!("{:?}", kp);
        assert!(!debug.contains("[4, 5, 6]"));
        assert!(debug.contains("secret_key_len"));
    }
}
