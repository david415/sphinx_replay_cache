// errors.rs - Sphinx replay cache errors.
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::fmt;
use std::io::Error as IoError;
use std::error::Error;

use ecdh_wrapper::errors::KeyError;


#[derive(Debug)]
pub enum MixKeyError {
    CreateCacheFailed,
    LoadCacheFailed,
    KeyError(KeyError),
    IoError(IoError),
    SledError,
}

impl fmt::Display for MixKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MixKeyError::*;
        match self {
            CreateCacheFailed => write!(f, "Failed to create cache."),
            LoadCacheFailed => write!(f, "Failed to load cache."),
            KeyError(x) => x.fmt(f),
            IoError(x) => x.fmt(f),
            SledError => write!(f, "Failed to set page cache key."),
        }
    }
}

impl Error for MixKeyError {
    fn description(&self) -> &str {
        "I'm a MixKeyError."
    }

    fn cause(&self) -> Option<&Error> {
        use self::MixKeyError::*;
        match self {
            CreateCacheFailed => None,
            LoadCacheFailed => None,
            KeyError(x) => x.cause(),
            IoError(x) => x.cause(),
            SledError => None,
        }
    }
}

impl From<KeyError> for MixKeyError {
    fn from(error: KeyError) -> Self {
        MixKeyError::KeyError(error)
    }
}

impl From<IoError> for MixKeyError {
    fn from(error: IoError) -> Self {
        MixKeyError::IoError(error)
    }
}
