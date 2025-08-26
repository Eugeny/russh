use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Pageant not found")]
    NotFound,

    #[error("Buffer overflow")]
    Overflow,

    #[error("No response from Pageant")]
    NoResponse,

    #[error("Invalid Cookie")]
    InvalidCookie,

    #[cfg(windows)]
    #[error(transparent)]
    WindowsError(#[from] windows::core::Error),
}
