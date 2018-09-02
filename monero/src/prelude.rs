/*
 * prelude.rs
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

//! "Prelude" module, to re-export various commonly used symbols.
//! Add `use wallet_gen::prelude::*;` in your code.

use std::result;

pub use error::Error;

/// Alias for [`std::result::Result`].
///
/// [`std::result::Result`]: https://doc.rust-lang.org/stable/std/result/enum.Result.html
pub type StdResult<T, E> = result::Result<T, E>;

/// Type alias of `Result` that uses the crate's [`Error`] type.
///
/// [`Error`]: ../error/enum.Error.html
pub type Result<T> = StdResult<T, Error>;
