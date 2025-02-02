//! SSH private key support.
//!
//! Support for decoding SSH private keys from the OpenSSH file format:
//!
//! <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>

#[cfg(feature = "alloc")]
mod dsa;
#[cfg(feature = "ecdsa")]
mod ecdsa;
mod ed25519;
#[cfg(feature = "alloc")]
mod rsa;

#[cfg(feature = "ecdsa")]
pub use self::ecdsa::{EcdsaKeypair, EcdsaPrivateKey};
pub use self::ed25519::{Ed25519Keypair, Ed25519PrivateKey};
#[cfg(feature = "alloc")]
pub use self::{
    dsa::{DsaKeypair, DsaPrivateKey},
    rsa::RsaKeypair,
};

use crate::{
    base64::{Decode, DecoderExt},
    public, Algorithm, CipherAlg, Error, KdfAlg, KdfOptions, PublicKey, Result,
};
use core::str::FromStr;
use pem_rfc7468::{self as pem, PemLabel};

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Line width used by the PEM encoding of OpenSSH private keys
const PEM_LINE_WIDTH: usize = 70;

/// SSH private key.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    /// Cipher algorithm (a.k.a. `ciphername`).
    pub cipher_alg: CipherAlg,

    /// KDF algorithm.
    pub kdf_alg: KdfAlg,

    /// KDF options.
    pub kdf_options: KdfOptions,

    /// Key data.
    pub key_data: KeypairData,

    /// Comment on the key (e.g. email address).
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub comment: String,
}

impl PrivateKey {
    /// Magic string used to identify keys in this format.
    pub const AUTH_MAGIC: &'static [u8] = b"openssh-key-v1\0";

    /// Parse an OpenSSH-formatted private key.
    ///
    /// OpenSSH-formatted private keys begin with the following:
    ///
    /// ```text
    /// -----BEGIN OPENSSH PRIVATE KEY-----
    /// ```
    pub fn from_openssh(input: impl AsRef<[u8]>) -> Result<Self> {
        let mut pem_decoder = pem::Decoder::new_wrapped(input.as_ref(), PEM_LINE_WIDTH)?;

        if pem_decoder.type_label() != Self::TYPE_LABEL {
            return Err(Error::Pem);
        }

        let mut auth_magic = [0u8; Self::AUTH_MAGIC.len()];
        pem_decoder.decode(&mut auth_magic)?;

        if auth_magic != Self::AUTH_MAGIC {
            return Err(Error::FormatEncoding);
        }

        let cipher_alg = CipherAlg::decode(&mut pem_decoder)?;
        let kdf_alg = KdfAlg::decode(&mut pem_decoder)?;
        let kdf_options = KdfOptions::decode(&mut pem_decoder)?;
        let nkeys = pem_decoder.decode_u32()? as usize;

        // TODO(tarcieri): support more than one key?
        if nkeys != 1 {
            return Err(Error::Length);
        }

        for _ in 0..nkeys {
            // TODO(tarcieri): validate decoded length
            let _len = pem_decoder.decode_u32()? as usize;
            let _pubkey = public::KeyData::decode(&mut pem_decoder)?;
        }

        // Begin decoding unencrypted list of N private keys
        // See OpenSSH PROTOCOL.key § 3
        // TODO(tarcieri): validate decoded length
        let _len = pem_decoder.decode_u32()? as usize;
        let checkint1 = pem_decoder.decode_u32()?;
        let checkint2 = pem_decoder.decode_u32()?;

        if checkint1 != checkint2 {
            // TODO(tarcieri): treat this as a cryptographic error?
            return Err(Error::FormatEncoding);
        }

        let key_data = KeypairData::decode(&mut pem_decoder)?;

        #[cfg(feature = "alloc")]
        let comment = pem_decoder.decode_string()?;

        // TODO(tarcieri): parse/validate padding bytes?
        Ok(Self {
            cipher_alg,
            kdf_alg,
            kdf_options,
            key_data,
            #[cfg(feature = "alloc")]
            comment,
        })
    }

    /// Get the digital signature [`Algorithm`] used by this key.
    pub fn algorithm(&self) -> Algorithm {
        self.key_data.algorithm()
    }

    /// Get the [`PublicKey`] which corresponds to this private key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key_data: public::KeyData::from(&self.key_data),
            #[cfg(feature = "alloc")]
            comment: self.comment.clone(),
        }
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> PublicKey {
        private_key.public_key()
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> PublicKey {
        private_key.public_key()
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_openssh(s)
    }
}

impl PemLabel for PrivateKey {
    const TYPE_LABEL: &'static str = "OPENSSH PRIVATE KEY";
}

/// Private key data.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeypairData {
    /// Digital Signature Algorithm (DSA) keypair.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Dsa(DsaKeypair),

    /// ECDSA keypair.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    Ecdsa(EcdsaKeypair),

    /// Ed25519 keypair.
    Ed25519(Ed25519Keypair),

    /// RSA keypair.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Rsa(RsaKeypair),
}

impl KeypairData {
    /// Get the [`Algorithm`] for this private key.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(_) => Algorithm::Dsa,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.algorithm(),
            Self::Ed25519(_) => Algorithm::Ed25519,
            #[cfg(feature = "alloc")]
            Self::Rsa(_) => Algorithm::Rsa,
        }
    }

    /// Get DSA keypair if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn dsa(&self) -> Option<&DsaKeypair> {
        match self {
            Self::Dsa(key) => Some(key),
            _ => None,
        }
    }

    /// Get ECDSA private key if this key is the correct type.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn ecdsa(&self) -> Option<&EcdsaKeypair> {
        match self {
            Self::Ecdsa(keypair) => Some(keypair),
            _ => None,
        }
    }

    /// Get Ed25519 private key if this key is the correct type.
    pub fn ed25519(&self) -> Option<&Ed25519Keypair> {
        match self {
            Self::Ed25519(key) => Some(key),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Get RSA keypair if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn rsa(&self) -> Option<&RsaKeypair> {
        match self {
            Self::Rsa(key) => Some(key),
            _ => None,
        }
    }

    /// Is this key a DSA key?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_dsa(&self) -> bool {
        matches!(self, Self::Dsa(_))
    }

    /// Is this key an ECDSA key?
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, Self::Ecdsa(_))
    }

    /// Is this key an Ed25519 key?
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519(_))
    }

    /// Is this key an RSA key?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa(_))
    }
}

impl Decode for KeypairData {
    fn decode(decoder: &mut impl DecoderExt) -> Result<Self> {
        match Algorithm::decode(decoder)? {
            #[cfg(feature = "alloc")]
            Algorithm::Dsa => DsaKeypair::decode(decoder).map(Self::Dsa),
            #[cfg(feature = "ecdsa")]
            Algorithm::Ecdsa(curve) => match EcdsaKeypair::decode(decoder)? {
                keypair if keypair.curve() == curve => Ok(Self::Ecdsa(keypair)),
                _ => Err(Error::Algorithm),
            },
            Algorithm::Ed25519 => Ed25519Keypair::decode(decoder).map(Self::Ed25519),
            #[cfg(feature = "alloc")]
            Algorithm::Rsa => RsaKeypair::decode(decoder).map(Self::Rsa),
            #[allow(unreachable_patterns)]
            _ => Err(Error::Algorithm),
        }
    }
}

impl From<&KeypairData> for public::KeyData {
    fn from(keypair_data: &KeypairData) -> public::KeyData {
        match keypair_data {
            #[cfg(feature = "alloc")]
            KeypairData::Dsa(dsa) => public::KeyData::Dsa(dsa.into()),
            #[cfg(feature = "ecdsa")]
            KeypairData::Ecdsa(ecdsa) => public::KeyData::Ecdsa(ecdsa.into()),
            KeypairData::Ed25519(ed25519) => public::KeyData::Ed25519(ed25519.into()),
            #[cfg(feature = "alloc")]
            KeypairData::Rsa(rsa) => public::KeyData::Rsa(rsa.into()),
        }
    }
}
