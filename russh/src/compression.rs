use std::convert::TryFrom;

use delegate::delegate;
use ssh_encoding::Encode;

#[cfg(feature = "flate2")]
use crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN;

#[derive(Debug, Clone)]
pub enum Compression {
    None,
    #[cfg(feature = "flate2")]
    Zlib,
    #[cfg(feature = "flate2")]
    ZlibOpenSSH,
}

#[derive(Debug)]
pub enum Compress {
    None,
    #[cfg(feature = "flate2")]
    Zlib(flate2::Compress),
}

#[derive(Debug)]
pub enum Decompress {
    None,
    #[cfg(feature = "flate2")]
    Zlib(flate2::Decompress),
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl Encode for Name {
    delegate! { to self.as_ref() {
        fn encoded_len(&self) -> Result<usize, ssh_encoding::Error>;
        fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error>;
    }}
}

impl TryFrom<&str> for Name {
    type Error = ();
    fn try_from(s: &str) -> Result<Name, ()> {
        ALL_COMPRESSION_ALGORITHMS
            .iter()
            .find(|x| x.0 == s)
            .map(|x| **x)
            .ok_or(())
    }
}

pub const NONE: Name = Name("none");
#[cfg(feature = "flate2")]
pub const ZLIB: Name = Name("zlib");
#[cfg(feature = "flate2")]
pub const ZLIB_LEGACY: Name = Name("zlib@openssh.com");

pub const ALL_COMPRESSION_ALGORITHMS: &[&Name] = &[
    &NONE,
    #[cfg(feature = "flate2")]
    &ZLIB,
    #[cfg(feature = "flate2")]
    &ZLIB_LEGACY,
];

#[cfg(feature = "flate2")]
impl Compression {
    pub fn new(name: &Name) -> Self {
        if name == &ZLIB {
            Compression::Zlib
        } else if name == &ZLIB_LEGACY {
            Compression::ZlibOpenSSH
        } else {
            Compression::None
        }
    }

    pub fn init_compress(&self, comp: &mut Compress) {
        match *self {
            Compression::Zlib | Compression::ZlibOpenSSH => {
                if let Compress::Zlib(ref mut c) = *comp {
                    c.reset()
                } else {
                    *comp =
                        Compress::Zlib(flate2::Compress::new(flate2::Compression::fast(), true))
                }
            }
            Compression::None => {
                *comp = Compress::None;
            }
        }
    }

    pub fn init_decompress(&self, comp: &mut Decompress) {
        match *self {
            Compression::Zlib | Compression::ZlibOpenSSH => {
                if let Decompress::Zlib(ref mut c) = *comp {
                    c.reset(true)
                } else {
                    *comp = Decompress::Zlib(flate2::Decompress::new(true))
                }
            }
            Compression::None => {
                *comp = Decompress::None;
            }
        }
    }
}

impl Compression {
    /// Returns true if compression should be deferred until after authentication.
    /// "zlib@openssh.com" defers; RFC 4253 "zlib" does not.
    pub fn is_deferred(&self) -> bool {
        match self {
            #[cfg(feature = "flate2")]
            Compression::ZlibOpenSSH => true,
            _ => false,
        }
    }
}

#[cfg(not(feature = "flate2"))]
impl Compression {
    pub fn new(_name: &Name) -> Self {
        Compression::None
    }

    pub fn init_compress(&self, _: &mut Compress) {}

    pub fn init_decompress(&self, _: &mut Decompress) {}
}

#[cfg(not(feature = "flate2"))]
impl Compress {
    pub fn compress<'a>(
        &mut self,
        input: &'a [u8],
        _: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        Ok(input)
    }

    pub fn compress_into(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        start_len: usize,
    ) -> Result<usize, crate::Error> {
        output.truncate(start_len);
        output.extend_from_slice(input);
        Ok(input.len())
    }
}

#[cfg(not(feature = "flate2"))]
impl Decompress {
    pub fn decompress<'a>(
        &mut self,
        input: &'a [u8],
        _: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        Ok(input)
    }
}

#[cfg(all(test, feature = "flate2"))]
mod tests {
    use std::io::Write;

    use flate2::write::ZlibEncoder;

    use super::*;

    #[test]
    fn decompressed_packet_at_limit_is_accepted() {
        let payload = vec![b'A'; MAXIMUM_DECOMPRESSED_PACKET_LEN];
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decompressor = Decompress::Zlib(flate2::Decompress::new(true));
        let mut output = Vec::new();

        let decompressed = decompressor.decompress(&compressed, &mut output).unwrap();
        assert_eq!(decompressed.len(), MAXIMUM_DECOMPRESSED_PACKET_LEN);
    }

    #[test]
    fn oversized_decompressed_packet_is_rejected() {
        let payload = vec![b'A'; MAXIMUM_DECOMPRESSED_PACKET_LEN + 1024];
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decompressor = Decompress::Zlib(flate2::Decompress::new(true));
        let mut output = Vec::new();

        let err = decompressor.decompress(&compressed, &mut output).unwrap_err();
        assert!(
            matches!(err, crate::Error::PacketSize(len) if len > MAXIMUM_DECOMPRESSED_PACKET_LEN)
        );
    }

    #[test]
    fn empty_compressed_packet_does_not_spin() {
        let compressed = Vec::new();
        let mut decompressor = Decompress::Zlib(flate2::Decompress::new(true));
        let mut output = Vec::new();

        let decompressed = decompressor.decompress(&compressed, &mut output).unwrap();
        assert!(decompressed.is_empty());
    }
}

#[cfg(feature = "flate2")]
impl Compress {
    fn zlib_output_reserve_bound(input_len: usize) -> usize {
        input_len.saturating_add(10)
    }

    pub fn compress<'a>(
        &mut self,
        input: &'a [u8],
        output: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        match *self {
            Compress::None => Ok(input),
            Compress::Zlib(ref mut z) => {
                output.clear();
                let n_in = z.total_in() as usize;
                let n_out = z.total_out() as usize;
                output.resize(input.len() + 10, 0);
                let flush = flate2::FlushCompress::Partial;
                loop {
                    let n_in_ = z.total_in() as usize - n_in;
                    let n_out_ = z.total_out() as usize - n_out;
                    #[allow(clippy::indexing_slicing)] // length checked
                    let c = z.compress(&input[n_in_..], &mut output[n_out_..], flush)?;
                    match c {
                        flate2::Status::BufError => {
                            output.resize(output.len() * 2, 0);
                        }
                        _ => break,
                    }
                }
                let n_out_ = z.total_out() as usize - n_out;
                #[allow(clippy::indexing_slicing)] // length checked
                Ok(&output[..n_out_])
            }
        }
    }

    pub fn compress_into(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        start_len: usize,
    ) -> Result<usize, crate::Error> {
        match *self {
            Compress::None => {
                output.truncate(start_len);
                output.extend_from_slice(input);
                Ok(input.len())
            }
            Compress::Zlib(ref mut z) => {
                output.truncate(start_len);
                let n_in = z.total_in() as usize;
                let n_out = z.total_out() as usize;
                let reserve = Self::zlib_output_reserve_bound(input.len());
                output.resize(start_len + reserve, 0);
                let flush = flate2::FlushCompress::Partial;
                loop {
                    let n_in_ = z.total_in() as usize - n_in;
                    let n_out_ = z.total_out() as usize - n_out;
                    #[allow(clippy::indexing_slicing)] // length checked
                    let c = z.compress(&input[n_in_..], &mut output[start_len + n_out_..], flush)?;
                    match c {
                        flate2::Status::BufError => {
                            let growth = output.len().saturating_sub(start_len).max(1);
                            output.resize(output.len() + growth, 0);
                        }
                        _ => break,
                    }
                }
                let n_out_ = z.total_out() as usize - n_out;
                output.truncate(start_len + n_out_);
                Ok(n_out_)
            }
        }
    }
}

#[cfg(feature = "flate2")]
impl Decompress {
    pub fn decompress<'a>(
        &mut self,
        input: &'a [u8],
        output: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        match *self {
            Decompress::None => Ok(input),
            Decompress::Zlib(ref mut z) => {
                output.clear();
                let n_in = z.total_in() as usize;
                let n_out = z.total_out() as usize;
                let max_output_len = MAXIMUM_DECOMPRESSED_PACKET_LEN
                    .checked_add(1)
                    .ok_or(crate::Error::PacketSize(usize::MAX))?;
                output.resize(input.len().clamp(1, max_output_len), 0);
                let flush = flate2::FlushDecompress::None;
                loop {
                    let n_in_ = z.total_in() as usize - n_in;
                    let n_out_ = z.total_out() as usize - n_out;
                    #[allow(clippy::indexing_slicing)] // length checked
                    let d = z.decompress(&input[n_in_..], &mut output[n_out_..], flush);
                    match d? {
                        flate2::Status::Ok | flate2::Status::BufError => {
                            let consumed_all_input = n_in_ == input.len();
                            let output_full = n_out_ == output.len();

                            if !output_full && consumed_all_input {
                                break;
                            }

                            if output_full {
                                if output.len() == max_output_len {
                                    break;
                                }
                                let next_len = output
                                    .len()
                                    .checked_mul(2)
                                    .map(|len| len.min(max_output_len))
                                    .ok_or(crate::Error::PacketSize(usize::MAX))?;
                                output.resize(next_len, 0);
                            }
                        }
                        _ => break,
                    }
                }
                let n_out_ = z.total_out() as usize - n_out;
                if n_out_ > MAXIMUM_DECOMPRESSED_PACKET_LEN {
                    return Err(crate::Error::PacketSize(n_out_));
                }
                #[allow(clippy::indexing_slicing)] // length checked
                Ok(&output[..n_out_])
            }
        }
    }
}
