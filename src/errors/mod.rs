mod crypto;
mod database;

pub use crypto::*;
pub use database::*;

#[derive(Debug)]
pub enum Error {
    IO { e: std::io::Error },
    DatabaseIntegrity { e: DatabaseIntegrityError },
    IncorrectKey,
    InvalidKeyFile,
}

impl std::error::Error for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO { e } => Some(e),
            Error::DatabaseIntegrity { e } => e.source(),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "KDBX error: {}",
            match self {
                Error::IO { e } => format!("IO error: {}", e),
                Error::IncorrectKey => "Incorrect key specified".to_owned(),
                Error::InvalidKeyFile => "Keyfile format invalid".to_owned(),
                Error::DatabaseIntegrity { e } => format!("{}", e),
            }
        )
    }
}

impl From<std::io::Error> for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: std::io::Error) -> Self {
        Error::IO { e }
    }
}
