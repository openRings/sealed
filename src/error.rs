use thiserror::Error;

#[derive(Debug, Error)]
pub enum SealedError {
    #[error("{0}")]
    Arg(String),
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    VarNotFound(String),
    #[error("{0}")]
    EnvFile(String),
}

impl SealedError {
    pub fn exit_code(&self) -> i32 {
        match self {
            SealedError::VarNotFound(_) => 1,
            SealedError::Crypto(_) => 2,
            SealedError::Arg(_) => 3,
            SealedError::EnvFile(_) => 4,
        }
    }
}
