// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! SMTree secret.

#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::error::TreeError;
use rand::{CryptoRng, RngCore};

/// The length of an SMTree `Secret`, in bytes.
pub const SECRET_LENGTH: usize = 32;
pub const ALL_ZEROS_SECRET: Secret = Secret([0u8; 32]);

/// An SMTree secret.
///
/// Instances of this secret are automatically overwritten with zeroes when they
/// fall out of scope.
#[derive(Zeroize)]
#[zeroize(drop)] // Overwrite secret key material with null bytes when it goes out of scope.
pub struct Secret(pub(crate) [u8; SECRET_LENGTH]);

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Secret {
    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SECRET_LENGTH] {
        &self.0
    }

    /// Construct a `Secret` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # fn doctest() -> Result<SecretKey, SignatureError> {
    /// use smtree::pad_secret::{Secret, SECRET_LENGTH};
    /// let secret_bytes: [u8; SECRET_LENGTH] = [
    ///    112, 012, 187, 211, 011, 092, 030, 001,
    ///    225, 255, 000, 166, 112, 236, 044, 196,
    ///    068, 073, 197, 105, 123, 050, 105, 025,
    ///    112, 059, 172, 003, 028, 174, 127, 096, ];
    ///
    /// let secret: Secret = Secret::from_bytes(&secret_bytes)?;
    /// #
    /// # Ok(secret)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = doctest();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an SMTree `Secret` or whose error value
    /// is an `SignatureError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Secret, TreeError> {
        if bytes.len() != SECRET_LENGTH {
            return Err(TreeError::SecretError);
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(Secret(bits))
    }

    /// Generate a `Secret` from a `csprng`.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    ///
    /// # #[cfg(feature = "std")]
    /// # fn main() {
    /// #
    /// use rand::rngs::OsRng;
    ///
    /// let mut csprng = OsRng{};
    /// let secret_key: Secret = Secret::generate(&mut csprng);
    /// # }
    /// ```
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand::OsRng`
    pub fn generate<T>(csprng: &mut T) -> Secret
    where
        T: CryptoRng + RngCore,
    {
        let mut sk: Secret = Secret([0u8; 32]);
        csprng.fill_bytes(&mut sk.0);
        sk
    }
}
