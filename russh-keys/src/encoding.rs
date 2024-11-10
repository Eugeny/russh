// Copyright 2016 Pierre-Étienne Meunier
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

#[doc(hidden)]
pub trait Bytes {
    fn bytes(&self) -> &[u8];
}

impl<A: AsRef<str>> Bytes for A {
    fn bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }
}

/// Encoding length of the given mpint.
#[allow(clippy::indexing_slicing)]
pub fn mpint_len(s: &[u8]) -> usize {
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1
    }
    (if s[i] & 0x80 != 0 { 5 } else { 4 }) + s.len() - i
}
