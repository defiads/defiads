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
//! defiads errors

use std::convert;
use std::fmt;
use std::io;
use crate::bitcoin_wallet;
use crate::bitcoin::blockdata::script;

/// An error class to offer a unified error interface upstream
pub enum Error {
    /// Unsupported
    Unsupported(&'static str),
    /// wallet related error
    Wallet(bitcoin_wallet::error::Error),
    /// IO error
    IO(io::Error),
    /// DB error
    DB(rusqlite::Error),
    /// script validation error
    Script(script::Error)
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Unsupported(ref s) => s,
            Error::Wallet(ref err) => err.description(),
            Error::IO(ref err) => err.description(),
            Error::DB(ref err) => err.description(),
            Error::Script(ref err) => err.description()
        }
    }

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::Unsupported(_) => None,
            Error::Wallet(ref err) => Some(err),
            Error::IO(ref err) => Some(err),
            Error::DB(ref err) => Some(err),
            Error::Script(ref err) => Some(err)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            Error::Unsupported(ref s) => write!(f, "Unsupported: {}", s),
            Error::Wallet(ref s) => write!(f, "{}", s),
            Error::IO(ref s) => write!(f, "{}", s),
            Error::DB(ref s) =>  write!(f, "{}", s),
            Error::Script(ref s) =>  write!(f, "{}", s),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &dyn fmt::Display).fmt(f)
    }
}

impl convert::From<bitcoin_wallet::error::Error> for Error {
    fn from(err: bitcoin_wallet::error::Error) -> Error {
        Error::Wallet(err)
    }
}

impl convert::From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl convert::From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Error {
        Error::DB(err)
    }
}

impl convert::From<std::net::AddrParseError> for Error {
    fn from(_: std::net::AddrParseError) -> Error {
        Error::IO(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

impl convert::From<serde_cbor::error::Error> for Error {
    fn from(_: serde_cbor::error::Error) -> Error {
        Error::IO(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

impl convert::From<bitcoin_hashes::Error> for Error {
    fn from(_: bitcoin_hashes::Error) -> Error {
        Error::IO(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

impl convert::From<bitcoin_hashes::hex::Error> for Error {
    fn from(_: bitcoin_hashes::hex::Error) -> Error {
        Error::IO(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

impl convert::From<script::Error> for Error {
    fn from(err: script::Error) -> Error {
        Error::Script(err)
    }
}
