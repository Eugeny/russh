use ssh_encoding::Encode;

#[doc(hidden)]
pub trait EncodedExt {
    fn encoded(&self) -> ssh_key::Result<Vec<u8>>;
}

impl<E: Encode> EncodedExt for E {
    fn encoded(&self) -> ssh_key::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;
        Ok(buf)
    }
}

pub struct NameList(pub Vec<String>);

impl NameList {
    pub fn as_encoded_string(&self) -> String {
        self.0.join(",")
    }
}

impl Encode for NameList {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        self.as_encoded_string().encoded_len()
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        self.as_encoded_string().encode(writer)
    }
}

#[macro_export]
#[doc(hidden)]
#[allow(clippy::crate_in_macro_def)]
macro_rules! map_err {
    ($result:expr) => {
        $result.map_err(|e| crate::Error::from(e))
    };
}

pub use map_err;
