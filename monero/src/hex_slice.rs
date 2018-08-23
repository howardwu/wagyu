/*
 * hex_slice.rs
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

//! Helper struct to easily create hex bytestrings from byte slices.

use std::fmt;
use std::ops::Deref;

/// A wrapper around a `&[u8]` byte slice that implements
/// various formatting traits, such as [`Display`],
/// [`LowerHex`], and [`UpperHex`] so it can be conveniently
/// used to format byte strings.
///
/// [`Display`]: https://doc.rust-lang.org/stable/std/fmt/trait.Display.html
/// [`UpperHex`]: https://doc.rust-lang.org/stable/std/fmt/trait.UpperHex.html
/// [`LowerHex`]: https://doc.rust-lang.org/stable/std/fmt/trait.LowerHex.html
#[derive(Debug, Copy, Clone, Hash)]
pub struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    /// Creates a new [`HexSlice`].
    ///
    /// [`HexSlice`]: ./struct.HexSlice.html
    pub fn new<T>(data: &'a T) -> Self
    where T: ?Sized + AsRef<[u8]> + 'a {
        HexSlice(data.as_ref())
    }

    /// Format the byte slice into a [`String`].
    ///
    /// [`String`]: https://doc.rust-lang.org/stable/std/string/struct.String.html
    pub fn format(&self) -> String { format!("{:x}", self) }
}

impl<'a> Deref for HexSlice<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target { self.0 }
}

impl<'a> AsRef<[u8]> for HexSlice<'a> {
    fn as_ref(&self) -> &[u8] { self.0 }
}

impl<'a> fmt::Display for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:x}", self) }
}

impl<'a> fmt::LowerHex for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<'a> fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

