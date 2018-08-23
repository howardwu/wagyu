/*
 * error.rs
 *
 * Copyright 2018 Standard Mining
 *
 * Available to be used and modified under the terms of the MIT License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

//! Error type for the crate.

use self::Error::*;
use either::Either;
use openssl::error as openssl;
use std::{error, fmt, io};

/// Enum that stores various possible error types when generating wallets.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    StaticMsg(&'static str),
    Msg(String),
    Io(io::Error),
    OpenSsl(Either<openssl::Error, openssl::ErrorStack>),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            StaticMsg(s) => s,
            Msg(ref s) => s,
            Io(ref e) => e.description(),
            OpenSsl(Either::Left(ref e)) => e.description(),
            OpenSsl(Either::Right(ref e)) => e.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            StaticMsg(_) | Msg(_) => None,
            Io(ref e) => Some(e),
            OpenSsl(Either::Left(ref e)) => Some(e),
            OpenSsl(Either::Right(ref e)) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", error::Error::description(self))
    }
}

// Auto-conversion
impl From<String> for Error {
    fn from(error: String) -> Self { Error::Msg(error) }
}

impl From<&'static str> for Error {
    fn from(error: &'static str) -> Self { Error::StaticMsg(error) }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self { Error::Io(error) }
}

impl From<openssl::Error> for Error {
    fn from(error: openssl::Error) -> Self { Error::OpenSsl(Either::Left(error)) }
}

impl From<openssl::ErrorStack> for Error {
    fn from(error: openssl::ErrorStack) -> Self { Error::OpenSsl(Either::Right(error)) }
}
