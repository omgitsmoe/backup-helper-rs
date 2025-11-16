#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashType {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    // NOTE: these require more attention due to having varying output sizes
    // Shake128,
    // Shake256,
    // Blake2s,
    // Blake2b,
}

impl HashType {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Sha3_224 => "sha3_224",
            Self::Md5 => "md5",
            // Self::Shake128 => "shake_128",
            // Self::Shake256 => "shake_256",
            // Self::Blake2s => "blake2s",
            // Self::Blake2b => "blake2b",
            Self::Sha3_512 => "sha3_512",
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha3_256 => "sha3_256",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Sha3_384 => "sha3_384",
            Self::Sha384 => "sha384",
        }
    }
}

impl TryFrom<&str> for HashType {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "sha3_224" => Ok(Self::Sha3_224),
            "md5" => Ok(Self::Md5),
            // "shake_128" => Ok(Self::Shake128),
            // "shake_256" => Ok(Self::Shake256),
            // "blake2s" => Ok(Self::Blake2s),
            // "blake2b" => Ok(Self::Blake2b),
            "sha3_512" => Ok(Self::Sha3_512),
            "sha1" => Ok(Self::Sha1),
            "sha224" => Ok(Self::Sha224),
            "sha3_256" => Ok(Self::Sha3_256),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            "sha3_384" => Ok(Self::Sha3_384),
            "sha384" => Ok(Self::Sha384),
            _ => Err(format!("Unsupported hash type: {}", value)),
        }
    }
}

impl TryFrom<&std::ffi::OsStr> for HashType {
    type Error = String;

    fn try_from(value: &std::ffi::OsStr) -> std::result::Result<Self, Self::Error> {
        let Some(str) = value.to_str() else {
            return Err(format!("Unsupported hash type: {:?}", value));
        };
        Self::try_from(str)
    }
}

impl From<HashType> for &'static str {
    fn from(val: HashType) -> Self {
        val.to_str()
    }
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
