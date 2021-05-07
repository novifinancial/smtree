// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This module provides definitions of errors might be returned by this library.

use crate::index::MAX_HEIGHT;

/// Errors occur during deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodingError {
    /// Decoded tree height or index height exceeds [MAX_HEIGHT]
    ExceedMaxHeight,
    /// Provided index does not fit to the tree
    IndexOverflow,
    /// There are more bytes than required for deserialization.
    TooManyEncodedBytes,
    /// Bytes are not enough for deserialization.
    BytesNotEnough,
    /// Error when decoding customized data type.
    ValueDecodingError {
        /// ```msg``` is the error message.
        msg: String,
    },
}

impl core::fmt::Display for DecodingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodingError::ExceedMaxHeight => {
                write!(
                    f,
                    "The height exceeds the maximum height, {}, in an SMT.",
                    MAX_HEIGHT
                )?;
            }
            DecodingError::IndexOverflow => {
                write!(f, "Index Overflow")?;
            }
            DecodingError::TooManyEncodedBytes => {
                write!(f, "Too many encoded bytes than required")?;
            }
            DecodingError::BytesNotEnough => {
                write!(f, "Bytes are not enough for decoding.")?;
            }
            DecodingError::ValueDecodingError { msg } => {
                write!(f, "Value decoding error: {}", msg)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for DecodingError {}

/// Errors occur when operating on the SMT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// Error when the index of input leaf node doesn't match with that of the tree.
    HeightNotMatch,
    /// Error when the indexes are not sorted.
    IndexNotSorted,
    /// Error when there are duplicated indexes in the list.
    IndexDuplicated,
    /// Errors related to SMTree Secret.
    SecretError,
}

impl core::fmt::Display for TreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TreeError::HeightNotMatch => {
                write!(
                    f,
                    "The height of the index doesn't match with the height of the tree."
                )?;
            }
            TreeError::IndexNotSorted => {
                write!(f, "The indexes are not sorted.")?;
            }
            TreeError::IndexDuplicated => {
                write!(f, "There are duplicated indexes")?;
            }
            TreeError::SecretError => {
                write!(f, "Wrong Secret size")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for TreeError {}
