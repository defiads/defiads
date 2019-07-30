//
// Copyright 2019 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//! BiadNet errors

use std::convert;
use std::error::Error;
use std::fmt;
use std::io;
use crate::bitcoin_wallet::error::WalletError;

/// An error class to offer a unified error interface upstream
pub enum BiadNetError {
    /// Unsupported
    Unsupported(&'static str),
    /// wallet related error
    Wallet(WalletError),
    /// IO error
    IO(io::Error)
}

impl Error for BiadNetError {
    fn description(&self) -> &str {
        match *self {
            BiadNetError::Unsupported(ref s) => s,
            BiadNetError::Wallet(ref err) => err.description(),
            BiadNetError::IO(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            BiadNetError::Unsupported(_) => None,
            BiadNetError::Wallet(ref err) => Some(err),
            BiadNetError::IO(ref err) => Some(err)
        }
    }
}

impl fmt::Display for BiadNetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            BiadNetError::Unsupported(ref s) => write!(f, "Unsupported: {}", s),
            BiadNetError::Wallet(ref s) => write!(f, "{}", s),
            BiadNetError::IO(ref s) => write!(f, "{}", s),
        }
    }
}

impl fmt::Debug for BiadNetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &dyn fmt::Display).fmt(f)
    }
}

impl convert::From<WalletError> for BiadNetError {
    fn from(err: WalletError) -> BiadNetError {
        BiadNetError::Wallet(err)
    }
}

impl convert::From<io::Error> for BiadNetError {
    fn from(err: io::Error) -> BiadNetError {
        BiadNetError::IO(err)
    }
}